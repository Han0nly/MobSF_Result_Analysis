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
        self.cert_result = {}
        self.cert_result['v1_false'] = 0
        self.cert_result['v2_false'] = 0
        self.cert_result['v3_false'] = 0
        self.cert_result['sha1withrsa'] = 0
        self.cert_result['md5withrsa'] = 0
        self.cert_result['goodcert'] = 0
        for item in self.content:
            if item['certificate_analysis']:
                if 'good' in item['certificate_analysis']['description']:
                    self.cert_result['goodcert'] = self.cert_result['goodcert'] + 1
                elif 'SHA1withRSA' in item['certificate_analysis']['description']:
                    self.cert_result['sha1withrsa'] = self.cert_result['sha1withrsa'] + 1
                certificate_info = item['certificate_analysis']['certificate_info']
                split_info = certificate_info.split('\n')
                for line in split_info:
                    # v1 signature:
                    split_line = line.split(':')
                    if 'v1' in split_line[0]:
                        if 'True' not in split_line[1]:
                            self.cert_result['v1_false'] = self.cert_result['v1_false'] + 1
                    # v2 signature:
                    elif 'v2' in split_line[0]:
                        if 'True' not in split_line[1]:
                            self.cert_result['v2_false'] = self.cert_result['v2_false'] + 1
                    # v3 signature:
                    elif 'v3' in split_line[0]:
                        if 'True' not in split_line[1]:
                            self.cert_result['v3_false'] = self.cert_result['v3_false'] + 1

    def analyse_permissions(self):
        self.permissions = {}
        for item in self.content:
            if item['permissions']:
                for perm in item['permissions'].keys():
                    if item['permissions'][perm]['status'] == "dangerous":
                        if perm in self.permissions.keys():
                            self.permissions[perm] = self.permissions[perm] + 1
                        else:
                            self.permissions[perm] = 1
                    else:
                        continue

    def analyse_manifest(self):
        self.manifest = {}
        self.manifest['Clear_text'] = 0
        for item in self.content:
            for weakness in item['manifest_analysis']:
                # 判断cleartest选项
                if 'Clear' == weakness['title'][0:4]:
                    self.manifest['Clear_text'] = self.manifest['Clear_text'] + 1

    def binary_analysis(self):
        self.binary = {}
        self.binary['PIE'] = 0
        for item in self.content:
            for weakness in item['binary_analysis']:
                # 判断PIE选项
                if 'Position Independent Executable' in weakness['title']:
                    self.binary['PIE'] = self.binary['PIE'] + 1

    def code_analysis(self):
        self.code = {}
        for item in self.content:
            if item['code_analysis']:
                for weakness in item['code_analysis'].keys():
                    if item['code_analysis'][weakness]['level'] == "high":
                        if weakness in self.code.keys():
                            self.code[weakness] = self.code[weakness] + 1
                        else:
                            self.code[weakness] = 1
                    else:
                        continue

    def tracker_analysis(self):
        self.trackers = {}
        self.trackers['count'] = 0
        self.trackers['0-50'] = 0
        self.trackers['51-100'] = 0
        self.trackers['101-150'] = 0
        self.trackers['151-200'] = 0
        self.trackers['201-250'] = 0
        self.trackers['251-300'] = 0
        self.trackers['301+'] = 0
        for item in self.content:
            if item['trackers'] and item['trackers']['total_trackers']:
                self.trackers['count'] = self.trackers['count'] + item['trackers']['total_trackers']
                if item['trackers']['total_trackers']<=50:
                    self.trackers['0-50'] = self.trackers['0-50'] + 1
                elif item['trackers']['total_trackers']<=100:
                    self.trackers['0-50'] = self.trackers['51-100'] + 1
                elif item['trackers']['total_trackers']<=150:
                    self.trackers['0-50'] = self.trackers['101-150'] + 1
                elif item['trackers']['total_trackers']<=200:
                    self.trackers['0-50'] = self.trackers['151-200'] + 1
                elif item['trackers']['total_trackers']<=250:
                    self.trackers['0-50'] = self.trackers['201-250'] + 1
                elif item['trackers']['total_trackers']<=300:
                    self.trackers['0-50'] = self.trackers['251-300'] + 1
                else:
                    self.trackers['301+'] = self.trackers['301+'] + 1

    def virustotal(self):
        self.virus = 0
        for item in self.content:
            if item['virus_total']:
                if 'positives' in item['virus_total'].keys() and item['virus_total']['positives']>0:
                    self.virus=self.virus+1

    def exported_count(self):
        self.exported = {}
        self.exported['exported_activities'] = 0
        self.exported['exported_receivers'] = 0
        self.exported['exported_providers'] = 0
        self.exported['exported_services'] = 0
        for item in self.content:
            self.exported['exported_activities'] = self.exported['exported_activities'] + item['exported_count']['exported_activities']
            self.exported['exported_receivers'] = self.exported['exported_receivers'] + item['exported_count']['exported_receivers']
            self.exported['exported_providers'] = self.exported['exported_providers'] + item['exported_count']['exported_providers']
            self.exported['exported_services'] = self.exported['exported_services'] + item['exported_count']['exported_services']


    def analyse_all(self):
        self.analyse_certificate()
        self.analyse_permissions()
        self.analyse_manifest()
        self.binary_analysis()
        self.code_analysis()
        self.tracker_analysis()
        self.virustotal()
        self.exported_count()


def main():
    result = MobSF_result()
    result.analyse_all()
    with open('./result.txt','w') as f:
        f.write(f"{result.cert_result}\n")
        for key in result.cert_result.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.cert_result[key]/result.count))

        f.write(f"{result.permissions}\n")
        for key in result.permissions.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.permissions[key]/result.count))

        f.write(f"{result.binary}\n")
        for key in result.binary.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.binary[key]/result.count))

        f.write(f"{result.manifest}\n")
        for key in result.manifest.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.manifest[key]/result.count))

        f.write(f"{result.code}\n")
        for key in result.code.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.code[key]/result.count))

        f.write(f"{result.trackers}\n")
        for key in result.trackers.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.trackers[key]/result.count))

        f.write(f"{result.exported}\n")
        for key in result.exported.keys():
            f.write(f"{key}:"+"{:.2f}%\n".format(result.exported[key]/result.count))

        f.write(f"Virustotal_result:{result.virus}\n")
        f.write("Virustotal_result:" + "{:.2f}%\n".format(result.virus/result.count))



if __name__ == '__main__':
    main()
