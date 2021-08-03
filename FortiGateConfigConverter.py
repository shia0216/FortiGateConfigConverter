import glob


class FortiGateConfigConverter:
    def __init__(self, path: str, encode='UTF-8') -> None:
        self.encode = encode
        self.config = self.__read_config(path)
        self.policy = {
            'columns': [
                'status', 'uuid', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr',
                'action', 'schedule', 'service', 'nat', 'natip', 'utm-status',
                'av-profile', 'dnsfilter-profile', 'webfilter-profile',
                'ips-sensor', 'ssl-ssh-profile', 'application-list',
                'profile-protocol-options', 'logtraffic', 'other'
            ]
        }
        self.policy['rules'] = self.__extract_policies()

    def __read_config(self, path: str) -> list[str]:
        with open(path, 'r', encoding=self.encode) as f:
            return [line.strip() for line in f.readlines()]

    def __extract_policies(self) -> list[dict]:
        flag = False
        policies = []
        for syntax in self.config:
            if 'config firewall policy' in syntax:
                flag = True
            if flag:
                words = syntax.replace('" "', '"_"').split(' ')
                if words[0] == 'edit':
                    policy = {}
                    policy['pid'] = words[1]
                    policy['other'] = []
                elif words[0] == 'set':
                    if words[1] in self.policy['columns']:
                        params = " ".join(words[2:]).strip('"').split('"_"')
                        policy[words[1]] = params
                    else:
                        escape_str = ' '.join(words[1:]).replace('"', '\"')
                        policy['other'].append(escape_str)
                elif words[0] == 'next':
                    policies.append(policy)
                elif words[0] == 'end':
                    flag = False
                    break
        return policies

    @staticmethod
    def convert_wsv(target: dict, sepalater="\t", delimiter="\n") -> str:
        rows = []
        for rule in target['rules']:
            row = []
            for column in target['columns']:
                key_exist = True if column in rule.keys() else False
                cell = delimiter.join(rule[column]) if key_exist else '-'
                row.append(f'"{cell}"')
            rows.append(sepalater.join(row))
        return "\n".join(rows)


if __name__ == '__main__':
    for path in glob.glob('./*.conf'):
        fgcc = FortiGateConfigConverter(path)
        tsv = path.replace('.conf', '.tsv')
        with open(tsv, 'w', encoding='UTF-8') as f:
            f.write(FortiGateConfigConverter.convert_wsv(fgcc.policy))
