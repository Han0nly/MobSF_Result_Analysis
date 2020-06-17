import pymongo, json
import logging
import config


class MobSF_result:
    def __init__(self):
        """
        MobSF_result object constructor.
        """
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.dbip = config.dbip
        self.dbport = config.dbport
        self.dbname = config.dbname
        self.colname = config.colname

        self._connect()

    ##############################
    # Internal Methods #
    ##############################

    def _connect(self):
        client = pymongo.MongoClient(f'mongodb://{self.dbip}:{self.dbport}')
        db = client[self.dbname]
        self.conn = db[self.colname]
        self._getcontents()

    def _getcontents(self):
        self.content = []
        self.count = 0
        for item in self.conn.find():
            self.count = self.count+1
            self.content.append(item['result'])

    ##############################
    # External Methods #
    ##############################

    def write_contents2file(self, file_name: str = 'mobsf_result.json'):
        with open(file_name, 'w+') as f:
            f.write(json.dumps(self.content, ensure_ascii=False, indent=2))


    def analyse_certificate(self):
        self.v1_false = 0
        self.v2_false = 0
        self.v3_false = 0
        self.sha1withrsa = 0
        self.md5withrsa = 0
        for item in self.content:
            if 'good' in item['certificate_analysis']['description']:
                continue
            elif 'SHA1withRSA' in item['certificate_analysis']['description']:
                continue
            else:
                print(item['certificate_analysis']['description'])
            # print(item['certificate_analysis']['description'])
            # certificate_info = item['certificate_analysis']['certificate_info']
            # certificate_info.split('\n')
            # v1 signature:
            # v2 signature:
            # v3 signature:

    def analyse_all(self):
        self.analyse_certificate()


def main():
    result = MobSF_result()
    result.analyse_certificate()


if __name__ == '__main__':
    main()
