from utils.malware_signatures import split_signatures


path1 = "./test/virustotal-1c9e4bb8da3ece689dc6cc7eadf25494.json"
path2 = "./test/vt-e931d549c340cca59535fcbcc0b434cc.json"

print("Signatures for file 1:")
print(split_signatures(path1))
print("Signatures for file 2:")     
print(split_signatures(path2))