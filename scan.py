# handle grpc interaction with the node to scan the chain for github tx

import q
import githubqrl

GITHUB_MESSAGE_TX = '0F0F0003'
BLOCKHEIGHT = 454550
BLOCK_LAG = 7

# scan chain and update the db with new github message transaction data..

class Scan():
    def __init__(self, node="localhost:19009"):
        self.wrapper = q.QRL(node=node)

    def scan_chain(self, previous_blockheight, block_lag_parameter):
        current_blockheight = self.wrapper.node_status().node_info.block_height
        print("blockheight: ", current_blockheight)
        last_block = 0
        for block in range(previous_blockheight, current_blockheight-block_lag_parameter, 1):
            last_block = block
            z = self.wrapper.get_blockbynumber(block)
            for t in z.block.transactions:
                if t.WhichOneof('transactionType') == 'message':
                    print("message_tx:", githubqrl.bin2hstr(t.message.message_hash[:4]),
                          githubqrl.bin2hstr(t.transaction_hash), len(t.message.message_hash), "bytes", block)
                    if t.message.message_hash[:4] == bytes(githubqrl.hstr2bin(GITHUB_MESSAGE_TX)) and len(t.message.message_hash) == 80 and t.message.message_hash[4:5] == b'\x00':
                        d_pk = githubqrl.bin2hstr(t.message.message_hash[9:76])
                        github_id = int.from_bytes(t.message.message_hash[76:], byteorder='big')

                        if t.master_addr:                                                       #if slave then PK !-> address
                            addr_from = 'Q'+ githubqrl.bin2hstr(t.master_addr)
                        else:
                            addr_from = 'Q'+ githubqrl.bin2hstr(bytes(githubqrl.QRLHelper.getAddress(t.public_key)))

                        db_data = githubqrl.check_db_qrl_address(addr_from)
                        if db_data is not False and db_data["qrl_address"] == addr_from and db_data["pk"]==d_pk and db_data["seed"]:
                            githubqrl.add_qrl_address_to_index(addr_from)
                            githubqrl.add_qrl_address_to_message_list(addr_from)

                            githubqrl.write_db_qrl_address(addr_from,
                                                           {"qrl_address": addr_from,
                                                            "pk": d_pk,
                                                            "pk_message_txid": githubqrl.bin2hstr(t.transaction_hash),
                                                            "blockheight": block,
                                                            "github_id": github_id})
                        else:
                            pass
        githubqrl.set_db_blockheight(last_block+1)
        return

if __name__ == "__main__":
    print("Connecting to GRPC wrapper")
    wrap = Scan(node="35.178.79.137:19009")
    wrap.scan_chain(BLOCKHEIGHT, BLOCK_LAG)

