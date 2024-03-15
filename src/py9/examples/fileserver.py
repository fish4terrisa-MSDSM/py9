from py9 import (
    Py9Server,

    Errors,
    Fid,
    Qid,
    Stat,
    Types,
    Modes,
)

import sys
import os


class FileFid(Fid):
    def __init__(
            self,
            fid: int,
            path: str = '',
            qid: Qid = None,
    ) -> None:
        super().__init__(fid, path, qid)
        self.fs_fid = None

    def open_file(self, root: str):
        self.fs_fid = open(root + '/' + self.path, 'rb')

    def close_file(self):
        if self.fs_fid:
            self.fs_fid.close()

    def read_file(self, offset: int, count: int) -> bytes:
        if not self.fs_fid:
            raise Exception("No file opened")

        self.fs_fid.seek(offset)
        return self.fs_fid.read(count)

    def __del__(self):
        self.close_file()


class FileStat(Stat):
    @classmethod
    def from_path(
            cls,
            path: str,
            qid: Qid,
    ):
        _type = 77
        dev = 48
        if qid._type == Types.QTDIR:
            mode = Modes.DMDIR | Modes.DMREAD | Modes.DMEXEC
            name = path.split('/')[-1]
            if not name:
                name = '/'
            length = 0
        else:
            mode = Modes.DMREAD
            name = os.path.basename(path)
            length = os.path.getsize(path)
        atime = int(os.path.getatime(path))
        mtime = int(os.path.getmtime(path))
        uid = 'user'
        gid = 'group'
        muid = 'user'
        return cls(
            _type=_type,
            dev=dev,
            qid=qid,
            mode=mode,
            atime=atime,
            mtime=mtime,
            length=length,
            name=name,
            uid=uid,
            gid=gid,
            muid=muid,
        )


class FileServer(Py9Server):
    def __init__(
            self,
            ip: str,
            port: int,
            directory: str,
    ) -> None:
        super().__init__(ip, port)
        self.directory = directory

        self.path_num = -1
        self.paths: dict[str, int] = {}

    def check_file_type(self, path: str) -> Types:
        if os.path.isdir(self.directory + path):
            return Types.QTDIR
        if os.path.isfile(self.directory + path):
            return Types.QTFILE
        return None

    def get_path_num(self) -> int:
        self.path_num += 1
        if self.path_num > 256 ** 8 - 1:
            self.path_num = 0

        return self.path_num

    def get_qid(self, path: str) -> Qid:
        if path in self.paths:
            return self.qids[self.paths[path]]
        path_num = self.get_path_num()
        file_type = self.check_file_type(path)
        if not file_type:
            return None
        qid = Qid(
            _type=file_type,
            version=0,
            path=path_num,
        )
        self.paths[path] = path_num
        self.qids[self.paths[path]] = qid
        return qid

    def handle_Tauth(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enoauth,
                data['tag'],
            )
        )

    def handle_Tattach(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        fid = data['fid']

        if fid in client.fids:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Edupfid,
                    data['tag'],
                )
            )
            return

        qid = self.get_qid('/')
        client.fids[fid] = FileFid(
            fid=fid,
            path='/',
            qid=qid,
        )
        client.socket.sendall(
            client._encode_Rattach(
                qid,
                data['tag'],
            )
        )

    def handle_Tflush(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Eperm,
                data['tag'],
            )
        )

    def handle_Twalk(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

        if data['fid'] not in client.fids:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Eunknownfid,
                    data['tag'],
                )
            )
            return

        if data['newfid'] in client.fids and data['fid'] != data['newfid']:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Edupfid,
                    data['tag'],
                )
            )
            return

        fid = client.fids[data['fid']]
        nfid = FileFid(
            fid=data['newfid'],
            path=fid.path,
        )

        first_loop = True
        failed = False
        new_path = fid.path
        qids: [Qid] = []

        for p in data['wnames']:
            if not os.path.isdir(new_path):
                failed = True
                break
            if p == '..':
                if new_path != '/':
                    new_path = new_path.split('/')[0:-1].join('/')
            else:
                if os.path.exists(self.directory + '/' + new_path + '/' + p):
                    new_path = new_path + '/' + p
                else:
                    break
            first_loop = False
            qids.append(self.get_qid(new_path))

        if failed and first_loop:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Ewalknodir,
                    data['tag'],
                )
            )
            return

        nfid.path = new_path
        nfid.qid = self.get_qid(new_path)
        client.fids[data['newfid']] = nfid

        client.socket.sendall(
            client._encode_Rwalk(
                qids,
                data['tag'],
            )
        )

    def handle_Topen(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

        fid = data['fid']
        mode = Modes(data['mode'])

        if data['fid'] not in client.fids:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Eunknownfid,
                    data['tag'],
                )
            )
            return

        if mode != Modes.OREAD:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Enowrite,
                    data['tag'],
                )
            )
            return

        fid_c: FileFid = client.fids[fid]
        qid = fid_c.qid
        fid_c.open_file(self.directory)

        client.socket.sendall(
            client._encode_Ropen(
                qid,
                self.msize,
                data['tag'],
            )
        )

    def handle_Tcreate(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enocreate,
                data['tag'],
            )
        )

    def handle_Tread(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

        fid = data['fid']
        offset = data['offset']
        count = data['count']

        fid_c: FileFid = client.fids[fid]
        readed = fid_c.read_file(offset, count)

        client.socket.sendall(
            client._encode_Rread(
                readed,
                data['tag'],
            )
        )

    def handle_Twrite(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']
        client.socket.sendall(
            client._encode_Rerror(
                Errors.Enowrite,
                data['tag'],
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
                data['tag'],
            )
        )

    def handle_Tstat(self, d: dict):
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

        fid = client.fids[data['fid']]
        path = fid.path
        qid = fid.qid
        stat = FileStat.from_path(self.directory + path, qid)

        client.socket.sendall(
            client._encode_Rstat(
                [stat],
                data['tag'],
            )
        )

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
                print(fs.serve())
            except Exception:
                del fs
                raise
                break
