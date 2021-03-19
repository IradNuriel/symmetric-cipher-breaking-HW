from hashlib import sha256
import secrets

def id_to_handle(user_id):
    m = sha256()
    m.update("Rg5vhFkyH7VEqZd3Ne9V".encode("utf-8"))
    m.update(user_id.encode("utf-8"))
    h = m.hexdigest()
    # added the higher frequency letters more often so brute forcing a nice handle
    # is easier, we don't really want special characters here...
    alphabet = u"abcdefghijklmnopqrstuvwxyzaeiou_" 
    
    name = ""
    first_60_bits = int(h[:15], 16)
    for i in range(12):
        name += alphabet[ (first_60_bits >> 5*i) & 0b11111]
    
    return "{0}_{1}".format(name, h[15:])


if __name__ == "__main__":
    handle = ""
    user_id = 9826986369
    while not handle.startswith("irad_"):
        # user_id = secrets.token_hex(8) # this would be the correct thing to do
        user_id += 1
        handle = id_to_handle(str(user_id))
    print("UserID = {}\nHandle = {}".format(user_id, handle))
                