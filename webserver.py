# web api handling routines
# alter this from /api/qaddress to /api/add/qaddress and /api/remove/qaddress, plus could add /db/ for easy db lookup
# for testing..

import githubqrl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

SERVER_ADDRESS = ('127.0.0.1', 8081)


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        print(self.path)
        err = {"status": "error", "reason": ""}
        api_array = self.path.strip("/").split("/")
        try:
            githubqrl.hstr2bin(api_array[1][1:])
        except:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            err["reason"] = "invalid hexstring"
            self.wfile.write(bytes(json.dumps(err), 'utf8'))
            return

        if api_array[0] == 'api' and api_array[1][:1].capitalize() == 'Q' and githubqrl.QRLHelper.addressIsValid(githubqrl.hstr2bin(api_array[1][1:])) == True:
            qrl_address = api_array[1]
            self.send_response(200)
        else:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            err["reason"] = "invalid QRL address or api path"
            self.wfile.write(bytes(json.dumps(err), 'utf8'))
            return

        # check if qrl address is already in the db..and add new data
        q_db = githubqrl.check_db_qrl_address(qrl_address)
        if q_db==False:
            seed, pk = githubqrl.get_new_keys_from_unused_trees()
            githubqrl.write_db_qrl_address(qrl_address, {"qrl_address": qrl_address, "seed": seed, "pk": pk})
            githubqrl.add_qrl_address_to_index(qrl_address)
        # or simply return existing data
        else:
            pk = q_db["pk"]

        success = {"status" : "ok", "qrl_address" : qrl_address,  "delegated_public_key": pk}

        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(json.dumps(success), 'utf8'))

        return


def httpserver():
    print("starting http server thread")
    httpd = HTTPServer(SERVER_ADDRESS, testHTTPServer_RequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    pass

