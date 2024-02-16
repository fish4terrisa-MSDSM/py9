from py9 import Py9Server
from py9 import Errors

import sys


class FileServer(Py9Server):
    def __init__(
            self,
            ip: str,
            port: int,
            directory: str,
    ) -> None:
        super().__init__(ip, port)
        self.directory = directory

    def handle_Tauth(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enoauth,
                data['tag']
            )
        )

    def handle_Tattach(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Eperm,
                data['tag']
            )
        )

    def handle_Tflush(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rflush(
                Errors.Eperm,
                data['tag']
            )
        )

    def handle_Twalk(self, d: dict):
        raise NotImplementedError

    def handle_Topen(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

    def handle_Tcreate(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enocreate,
                data['tag']
            )
        )

    def handle_Tread(self, d: dict):
        raise NotImplementedError

    def handle_Twrite(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enowrite,
                data['tag']
            )
        )

    def handle_Tclunk(self, d: dict):
        raise NotImplementedError

    def handle_Tremove(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enoremove,
                data['tag']
            )
        )

    def handle_Tstat(self, d: dict):
        raise NotImplementedError

    def handle_Twstat(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enowstat,
                data['tag']
            )
        )


if __name__ == '__main__':
    try:
        fs = FileServer(
            ip=sys.argv[1],
            port=int(sys.argv[2]),
            directory=sys.argv[3],
        )
    except Exception:
        raise
    else:
        while True:
            try:
                fs.serve()
            except Exception:
                del fs
                raise
                break
