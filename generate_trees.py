# python3 script to prep the db with trees and variables
import githubqrl
import json
import time
import db

INITIAL_TREE_NUMBER = 200

trees = []

initial_prf_pool = bytes(githubqrl.shake256(INITIAL_TREE_NUMBER*48, githubqrl.hstr2bin(githubqrl.bot_credentials.SEED)))


for x in range(0,INITIAL_TREE_NUMBER,1):
    time_start = time.time()
    t, pk, sk, seed = githubqrl.create_xmss_tree(seed=initial_prf_pool[x*48:x*48+48])
    print("sk",type(sk), githubqrl.bin2hstr(bytes(sk)), len(githubqrl.bin2hstr(bytes(sk))))
    print("pk", type(pk), githubqrl.bin2hstr(bytes(pk)), len(githubqrl.bin2hstr(bytes(pk))))
    print("seed", type(seed), githubqrl.bin2hstr(bytes(seed)), len(githubqrl.bin2hstr(bytes(seed))))

    trees.append({"seed" : githubqrl.bin2hstr(bytes(seed)), "pk" : githubqrl.bin2hstr(bytes(pk))})
    print(time.time()-time_start)

print(trees)
print(json.dumps(trees))

db.d.set("unused_trees", json.dumps(trees))

