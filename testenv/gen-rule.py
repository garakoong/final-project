import sys

usage = "Usage: self {xdp-mfw | iptables} <nr_rules> [nr_modules]"

rule_key = []

for saddr in range (10):
    for daddr in range(10):
        for sport in range(4):
            for dport in range (4):
                for proto in ["tcp", "udp"]:
                    key = {
                        "saddr":f"192.168.100.{saddr+1}",
                        "daddr":f"192.168.200.{daddr+1}",
                        "proto":proto,
                        "sport":11000+sport,
                        "dport": 12000+dport
                    }
                    rule_key.append(key)

def gen_xdp_rule(nr_modules, nr_rules):
    print(f"#Generating {nr_modules} modules, {nr_rules} each for xdp-mfw...")
    print("set -xe")

    print ("cd ../module")

    module_name = [f"MODULE{i}" for i in range(1, nr_modules)]

    for i in range(len(module_name)):
        print(f"sudo ./xdp-mfw -N {module_name[i]} -s 192.168.{100+(i//250)}.{(i%250)+1} -j ACCEPT")

    module_name.append("MAIN")

    for m in module_name:
        for i in range(nr_rules):
            print(f"sudo ./xdp-mfw -A {m} -s {rule_key[i]['saddr']} -d {rule_key[i]['daddr']} -p {rule_key[i]['proto']} --sport {rule_key[i]['sport']} --dport {rule_key[i]['dport']} -j ACCEPT")
                                

def gen_iptables_rule(nr_modules, nr_rules):
    print(f"#Generating {nr_modules} modules, {nr_rules} each for iptables...")
    print("set -xe")

    module_name = []

    for i in range(nr_modules):
        m = f"MODULE{i+1}"
        
        print(f"sudo iptables -N {m} ")
        
        if i < nr_modules-1:
            print(f"sudo iptables -A INPUT -s 192.168.{100+(i//250)}.{(i%250)+1} -j {m}")
        else:
            print(f"sudo iptables -A INPUT -j {m}")
        module_name.append(m)

    if len(module_name) == 0:
        module_name.append("INPUT")

    for m in module_name:
        for i in range(nr_rules):
            print(f"sudo iptables -A {m} -s {rule_key[i]['saddr']} -d {rule_key[i]['daddr']} -p {rule_key[i]['proto']} --sport {rule_key[i]['sport']} --dport {rule_key[i]['dport']} -j ACCEPT")
        if m != "INPUT":
            print(f"sudo iptables -A {m} -j ACCEPT")
    

def gen_rule(fw, nr_modules, nr_rules):
    if fw == "iptables":
        gen_iptables_rule(nr_modules, nr_rules)
    elif fw == "xdp-mfw":
        gen_xdp_rule(nr_modules, nr_rules)
    else:
        raise Exception(f"Invalid firewall name. ('{fw}' given)")

def main():
    if len(sys.argv) < 3:
        print(usage)
        return

    fw = sys.argv[1]
    nr_rules = int(sys.argv[2])
    nr_modules = 0
    if len(sys.argv) > 3:
        nr_modules = int(sys.argv[3])

    if nr_rules > 3000 or nr_rules <= 0:
        raise Exception("<nr_rules> must be between 1 - 3000.")
    
    if nr_modules < 0 or nr_modules > 100:
        raise Exception("[nr_modules] must be between 1 - 100.")

    gen_rule(fw, nr_modules, nr_rules)

if __name__ == "__main__":
    main()
