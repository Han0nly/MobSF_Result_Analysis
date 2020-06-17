import os
for filename in os.listdir("/store/third_party_apks"):
    if filename[-4:]!=".apk":
        os.rename("/store/third_party_apks/"+filename,"/store/third_party_apks/"+filename+".apk")
        print(f"{filename}成功重命名为{filename}.apk")

