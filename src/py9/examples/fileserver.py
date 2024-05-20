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

    def open_file(self, fid: Fid):
        f_path = self.directory + '/' + fid.path
        if not os.path.isdir(f_path):
            fid.fs_fid = open(self.directory + '/' + fid.path, 'rb')
        else:
            fid.fs_fid = self.directory + '/' + fid.path

    def close_file(self, fid: Fid):
        if fid.fs_fid:
            if not isinstance(fid.fs_fid, str):
                fid.fs_fid.close()

    def read_file(self, fid: Fid, offset: int, count: int) -> bytes:
        if not fid.fs_fid:
            raise Exception("No file opened")

        if isinstance(fid.fs_fid, str):
            ret = b''
            fss = []
            for dir in os.listdir(fid.fs_fid):
                path = fid.fs_fid + '/' + dir
                qid: Qid = self.get_qid(path)
                fss.append(FileStat.from_path(path, qid))

            for fs in fss:
                ret += fs.to_bytes()
            return ret[offset:offset+count]

        else:
            fid.fs_fid.seek(offset)
            return fid.fs_fid.read(count)

    def check_file_type(self, path: str) -> Types:
        if os.path.isdir(self.directory + '/' + path):
            return Types.QTDIR
        if os.path.isfile(self.directory + '/' + path):
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
        client.fids[fid] = Fid(
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
        nfid = Fid(
            fid=data['newfid'],
            path=fid.path,
        )

        walk_nodir = True
        failed = False
        new_path = fid.path
        qids: [Qid] = []

        if not data['wnames']:
            nfid.path = fid.path
            nfid.qid = self.get_qid(fid.path)
            client.fids[data['newfid']] = nfid

            client.socket.sendall(
                client._encode_Rwalk(
                    qids,
                    data['tag'],
                )
            )
            return

        for p in map(lambda x: x.decode(), data['wnames']):
            if not os.path.isdir(self.directory + '/' + new_path):
                failed = True
                break
            walk_nodir = False
            if '/' in p:
                client.socket.sendall(
                    client._encode_Rerror(
                        Errors.Ebotch,
                        data['tag'],
                    )
                )
            if p == '..':
                if new_path != '/':
                    new_path = '/'.join(new_path.split('/')[0:-1])
            else:
                if os.path.exists(self.directory + '/' + new_path + '/' + p):
                    new_path = new_path + '/' + p
                else:
                    failed = True
                    break
            qids.append(self.get_qid(new_path))

        if failed and walk_nodir:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Ewalknodir,
                    data['tag'],
                )
            )
            return

        if not failed:
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
        try:
            mode = Modes(data['mode'])
        except ValueError:
            client.socket.sendall(
                client._encode_Rerror(
                    Errors.Enowrite,
                    data['tag'],
                )
            )
            return

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

        fid_c: Fid = client.fids[fid]
        qid = fid_c.qid
        self.open_file(fid_c)

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

        fid_c: Fid = client.fids[fid]
        readed = self.read_file(fid_c, offset, count)

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
        client: Py9Server.Client = self.clients[d['client_id']]
        data: dict = d['data']

        fid = data['fid']
        fid_c: Fid = client.fids[fid]
        self.close_file(fid_c)
        del client.fids[fid]

        client.socket.sendall(
            client._encode_Rclunk(
                data['tag'],
            )
        )

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
    if len(sys.argv) != 4:
        print('usage: fileserver IP PORT DIR')
        exit(-1)
    fs = FileServer(
        ip=sys.argv[1],
        port=int(sys.argv[2]),
        directory=sys.argv[3],
    )
    while True:
        try:
            print(fs.serve())
        except KeyboardInterrupt:
            del fs
            break
