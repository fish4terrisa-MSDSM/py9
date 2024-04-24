from .qid import Qid


class Fid:
    def __init__(
            self,
            fid: int,
            path: str = '',
            qid: Qid = None,
    ) -> None:
        self.fid = fid
        self.path: str = path
        self.qid: Qid = qid

        self.fs_fid = None
