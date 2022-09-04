import base64
s = "A top Secret!"

encode = s.encode("utf-8")
to_hex = base64.b16encode(encode)
print(to_hex)