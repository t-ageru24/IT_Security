import base64
s = "I owe you $3000."

encode = s.encode("utf-8")
to_hex = base64.b16encode(encode)
print(to_hex)