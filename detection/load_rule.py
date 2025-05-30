from detection.SnortRule import SnortRules
import os
import glob


# 配置日志


class  Load:
    """加载规则或者配置文件"""
    def __init__(self, ruleset_path = "./ruleset", config_path = "./config.json"):
        self.rules = []  # 存储解析成功的规则
        self.ruleset_path = ruleset_path
        self.config_path = config_path
    

    def load_rule(self):
        rule_files = None  # 初始化变量
        
        if os.path.isfile(self.ruleset_path):
            rule_files = self.ruleset_path
        elif os.path.isdir(self.ruleset_path):
            rule_files = glob.glob(os.path.join(self.ruleset_path,'**',"*.rules"),recursive=True)

        if not rule_files:
            raise FileNotFoundError(f"在{self.ruleset_path}中没有找到规则文件")
        
        else:
            for rule_file in rule_files:
                try:
                    with open(rule_file,'r',encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            rule = SnortRules(line)
                            self.rules.append(rule.get_rule_parse())
                            
                except (FileNotFoundError, PermissionError, UnicodeDecodeError, Exception) as e:
                    raise Exception(f"解析规则文件{rule_file}时发生错误: {str(e)}")
                
        return self.rules


                            

            


"""
加载规则后可传给match.py使用
rule_match = RuleMatch(rules)
"""
