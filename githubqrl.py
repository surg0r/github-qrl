# github-qrl signing code

from github import Github
import threading
import db
import json
import time
import scan
from os import urandom
from pyqrllib import pyqrllib
from pyqrllib.pyqrllib import bin2hstr, getRandomSeed, hstr2bin, str2bin, bin2mnemonic, mnemonic2bin, QRLHelper, shake256
import bot_credentials
import webserver



# db storage class

class QrlAddress():
    def __init__(self, qrl_address="", seed="", pk="", pk_message_txid="", github_login="", github_proof_url="",
                 gist_id="", validated=False, ots_key=0, github_id=None, blockheight=None):
        self.qrl_address=qrl_address
        self.seed = seed
        self.pk = pk
        self.pk_message_txid = pk_message_txid
        self.github_login = github_login
        self.github_proof_url = github_proof_url
        self.gist_id = gist_id
        self.validated = validated
        self.ots_key = ots_key
        self.github_id = github_id
        self.blockheight = blockheight


    def export_dict(self):
        return {"qrl_address": self.qrl_address,
                        "seed": self.seed,
                        "pk": self.pk,
                        "pk_message_txid" : self.pk_message_txid,
                        "blockheight": self.blockheight,
                        "github_id": self.github_id,
                        "github_login": self.github_login,
                        "github_proof_url": self.github_proof_url,
                        "gist_id": self.gist_id,
                        "validated": self.validated,
                        "ots_key": self.ots_key
                        }



# generate a random seed

def useed(n=48):
    return urandom(n)


# XMSS via pyqrllib within a class

class Tree():
    def __init__(self, seed=None, height=10):
        if not seed:
            seed = useed()
        if height <3 or height % 2 != 0:
            height = 10
        self.seed = seed
        self.hexseed = bin2hstr(self.seed)
        self.mnemonic = bin2mnemonic(self.seed)
        self.xmss = pyqrllib.XmssFast(seed, height)


        self.PK = self.xmss.getPK()
        self.SK = self.xmss.getSK()
        self.height = self.xmss.getHeight()
        self.signatures = 2**self.height
        self.address = self.xmss.getAddress()

    def set_index(self, index=None):
        if not index or index > 2**self.height:
            return False
        self.xmss.setIndex(index)
        return True

    def get_index(self):
        return self.xmss.getIndex()

    def remaining(self):
        return self.signatures-self.xmss.getIndex()

    def sign(self, message, index=None):
        if isinstance(message, bytes):
            return bytes(self.xmss.sign(tuple(message)))
        else:
            return bin2hstr(self.xmss.sign(tuple(message.encode())))

    def verify(self, message, signature, PK):
        return self.xmss.verify(tuple(message.encode()), hstr2bin(signature), PK)


def create_xmss_tree(seed=None, height=10):
    t = Tree(seed, height)
    return t, t.PK, t.SK, t.seed


def sign_xmss_tree(tree, message):
    return tree.sign(message)


# functions to ease access with github api and db to gather information..need to add error correction

def get_new_keys_from_unused_trees():
    utreesjs = json.loads(db.d.get("unused_trees"))
    new_keys = utreesjs.pop()
    seed = new_keys["seed"]
    pk = new_keys["pk"]
    db.d.set("unused_trees", json.dumps(utreesjs))
    return seed, pk


def get_pk_from_qrl_address(qrl_address):
    db_data =  db.d.get(qrl_address)
    if db_data == False:
        return False
    else:
        return db_data["pk"]

def get_txid_from_qrl_address(qrl_address):
    db_data =  db.d.get(qrl_address)
    if db_data == False:
        return False
    else:
        return db_data["pk_message_txid"]


def get_db_qrl_validated():                         #qrl validated lists all linked qrl-github accounts
    db_data = db.d.get("qrl_validated")
    if db_data == False:
        db.d.set("qrl_validated", [])
        return []
    else:
        return db_data

def add_qrl_address_to_validated(qrl_address):
    db_data = db.d.get("qrl_validated")
    if db_data == False:
        db.d.set("qrl_validated", [qrl_address])
    else:
        if qrl_address not in db_data:
            db_data.append(qrl_address)
            db.d.set("qrl_validated", db_data)
    return


def get_db_qrl_index():                             #qrl index lists all qrl addresses in the db
    db_data = db.d.get("qrl_index")
    if db_data == False:
        db.d.set("qrl_index", [])
        return []
    else:
        return db_data


def add_qrl_address_to_index(qrl_address):
    db_data = db.d.get("qrl_index")
    if db_data == False:
        db.d.set("qrl_index", [qrl_address])
    else:
        if qrl_address not in db_data:
            db_data.append(qrl_address)
            db.d.set("qrl_index", db_data)
    return


def get_db_message_list():                          #qrl message lists all qrl addresses with message_tx
    db_data = db.d.get("message_tx_list")
    if db_data==False:
        db.d.set("message_tx_list", [])
        return []
    else:
        return db_data

def add_qrl_address_to_message_list(qrl_address):
    db_data = db.d.get("message_tx_list")
    if db_data == False:
        db.d.set("message_tx_list", [qrl_address])
    else:
        if qrl_address not in db_data:
            db_data.append(qrl_address)
            db.d.set("message_tx_list", db_data)
    return


def check_db_qrl_address(qrl_address):              # is qrl address already in the db?
    db_data = db.d.get(qrl_address)
    if db_data == False:
        return False
    else:
        return db_data

def write_db_qrl_address(qrl_address, db_data):    #update the db entry as required
    existing_db_data=check_db_qrl_address(qrl_address)
    if existing_db_data==False:
            q=QrlAddress(qrl_address=qrl_address)
            existing_db_data=q.export_dict()
    for key in list(db_data):
        if key in list(existing_db_data):
                    existing_db_data[key] = db_data[key]
    db.d.set(qrl_address, existing_db_data)
    return

def set_db_blockheight(blockheight):
    db.d.set("BLOCKHEIGHT", blockheight)
    return


def get_db_blockheight():
    return db.d.get("BLOCKHEIGHT")


def get_github_id_from_qrl_address(qrl_address):
    db_data = db.d.get(qrl_address)
    if db_data == False:
        return False
    else:
        return db_data["github_id"]

def get_github_login_for_id(github_id):
    return g.get_users(github_id-1)[0].login

def set_github_login_for_id(qrl_address):
    user_db = db.d.get(qrl_address)
    user_db["github_login"] = get_github_login_for_id(user_db["github_id"])
    db.d.set(qrl_address, user_db)
    return

def get_github_user_object(github_id):
    return g.get_users(github_id-1)[0]

def get_latest_github_pull_req_obj(github_id):
    user_obj = get_github_user_object(github_id)
    events_obj = user_obj.get_events()
    for event in events_obj:
        if event.type == "PullRequestEvent" and event.payload["action"]=="opened":
            sha = event.payload["pull_request"]["head"]["sha"]
            org = g.get_organization(event.payload["pull_request"]["base"]["repo"]["owner"]["login"])
            re = org.get_repo(event.payload["pull_request"]["base"]["repo"]["name"])
            pr_obj = re.get_pull(event.payload["number"])
            return pr_obj, sha
    return False, False


def check_for_valid_gist(qrl_address):       #checks for valid gist and if so returns object
    pk = get_pk_from_qrl_address(qrl_address)
    github_id = get_github_id_from_qrl_address(qrl_address)
    if github_id == False:
        return False
    github_user_obj = get_github_user_object(github_id)
    gists = github_user_obj.get_gists()
    gist_id = ""
    gist_obj = None
    for gist in gists:
        gist_content = gist.files[list(gist.files)[0]].content
        if qrl_address in gist_content and pk in gist_content:
            gist_id = gist.id
            gist_obj = gist
            break
    if gist_id:
        return gist_obj
    return False

def update_db_gist_message_id(qrl_address, gist_obj):
    write_db_qrl_address(qrl_address, {"gist_id": gist_obj.id})
    return


def check_for_previous_gist_comment(gist_obj):      #1) does it exist? 2) if so, does it contain QRL?
    comments_obj = gist_obj.get_comments()
    if comments_obj.totalCount == 0:
        return False
    else:
        for comment in comments_obj:
            if "QRL transaction proof" in comment.body and comment.user.login == "qrl-signer":
                return True
    return False

def check_for_previous_create_issue_comment(github_obj):
    comments_obj = github_obj.get_issue_comments()
    if comments_obj.totalCount == 0:
        return False
    else:
        for comment in comments_obj:
            if "QRL transaction proof" in comment.body and comment.user.login == "qrl-signer":
                return True
    return False


def github_signing_create_issue_comment(github_obj, qrl_addr, sig, sha):
    github_obj.create_issue_comment("SHA " + sha + "\n"
                                    + "XMSS signature: " + sig + "\n"
                                    + "XMSS Public key: " + get_pk_from_qrl_address(qrl_addr) + "\n"
                                    + "QRL transaction proof: https://explorer.theqrl.org/tx/" + get_txid_from_qrl_address(qrl_addr) + "\n"
                                    + "QRL address: " + qrl_addr)
    return

def github_gist_create_comment(gist_obj, qrl_addr):
    gist_obj.create_comment("QRL address: " + qrl_addr + "\n"
                                  + "XMSS public key: " + get_pk_from_qrl_address(qrl_addr) + "\n"
                                  + "QRL transaction proof: https://explorer.theqrl.org/tx/" + get_txid_from_qrl_address(qrl_addr) + "\n"
                                  + "Github account id: " + str(get_github_id_from_qrl_address(qrl_addr)) + " linked for delegated signing!")
    return


def get_db_seed_and_ots_key(qrl_address):
    db_data = check_db_qrl_address(qrl_address)
    return db_data["seed"], db_data["ots_key"]


def db_increment_ots_key(qrl_address):
    db_data = check_db_qrl_address(qrl_address)
    db_data["ots_key"] +=1
    db.d.set(qrl_address, db_data)
    return


if __name__ == "__main__":

    print("connecting to github api")
    g = Github(bot_credentials.GITHUB_USERNAME, bot_credentials.GITHUB_PASSWORD)
    print("connecting to GRPC/qrl-node api")
    wrap = scan.Scan(node="35.178.79.137:19009")


    t = threading.Thread(target=webserver.httpserver)
    t.start()

    set_db_blockheight(scan.BLOCKHEIGHT)

    while True:
        try:

            # qrl_addresses on validated list..scan for new pull requests and sign/comment as required
            print("validator list, scanning for new pull requests to sign")
            validated_db_list = get_db_qrl_validated()
            for user in validated_db_list:
                github_id = get_github_id_from_qrl_address(user)
                pr_obj, sha = get_latest_github_pull_req_obj(github_id)
                if pr_obj is not False:
                    if check_for_previous_create_issue_comment(pr_obj) is False:
                        seed, ots_key = get_db_seed_and_ots_key(user)
                        t, pk, sk, seed = create_xmss_tree(seed=seed)
                        t.set_index(ots_key)
                        sig = sign_xmss_tree(t, sha)
                        db_increment_ots_key(user)
                        github_signing_create_issue_comment(pr_obj, user, sig, sha)

            # scan the chain to see if any new github message transactions have occurred
            print("scanning for github message transactions")
            blockheight = get_db_blockheight()
            wrap.scan_chain(blockheight, scan.BLOCK_LAG)

            # when messages have arrived but we are still waiting for github validation..check github
            print("scanning for github gists to validate and comment")
            message_db_list = get_db_message_list()
            for user in message_db_list:
                if user not in validated_db_list:
                    gist_obj = check_for_valid_gist(user)
                    if gist_obj is not False:
                        if check_for_previous_gist_comment(gist_obj) is False:
                            github_gist_create_comment(gist_obj, user)
                            update_db_gist_message_id(user, gist_obj)
                            add_qrl_address_to_validated(user)

            # sleep for a while
            print("going to sleep..")
            time.sleep(600)

        except KeyboardInterrupt:
            print("Shutting down..")
            exit()






