# NHQ3 Cipher
# by Karl Zander

s0 = ["S", "J", "H", "E", "K", "A", "W", "N", "T", "R", "D", "I", "Q", "M", "U", "V", "X", "Z", "C", "F", "B", "L", "P", "O", "G", "Y"]

def conv_to_num(text):
    n = []
    for letter in text:
        n.append(ord(letter) - 65)
    return n
    
def conv_to_letters(n):
    letters = ""
    for num in n:
        letters += chr(num + 65)
    return letters
    
def sub_text(s0, nums):
    for x in range(len(nums)):
        nums[x] = s0.index(nums[x])
    return nums
    
def sub_text_rev(s0, nums):
    for x in range(len(nums)):
        nums[x] = s0[nums[x]]
    return nums
    
def transpose(nums, block_len):
    t = []
    for x in range(len(nums) // 2):
        t.append(nums[x])
        t.append(nums[x + ((block_len) // 2)])
    return t
    
def transpose_rev(nums, block_len):
    t = []
    cn = list(nums)
    c = 0
    for x in range(len(nums) // 2):
        t.append(cn.pop(c))
        c += 1
    for x in range(len(nums) // 2):
        t.append(cn.pop(0))
    return t

def add_layerA(nums, block_len):
    for x in range(len(nums)):
        nums[(x + (block_len // 2)) % block_len] = (nums[x] + nums[(x + (block_len // 2)) % block_len]) % 26
    return nums
    
def sub_layerA(nums, block_len):
    for x in reversed(range(len(nums))):
        nums[(x + (block_len // 2)) % block_len] = (nums[(x + (block_len // 2)) % block_len] - nums[x]) % 26
    return nums
    
def add_layerB(nums, block_len):
    for x in range(len(nums)):
        nums[x] = (nums[x] + nums[(x + (block_len // 2)) % block_len]) % 26
    return nums
    
def sub_layerB(nums, block_len):
    for x in reversed(range(len(nums))):
        nums[x] = (nums[x] - nums[(x + (block_len // 2)) % block_len]) % 26
    return nums
        
def add_key(nums, key):
    for x in range(len(nums)):
        nums[x] = (nums[x] + key[x]) % 26
    return nums
    
def sub_key(nums, key):
    for x in range(len(nums)):
        nums[x] = (nums[x] - key[x]) % 26
    return nums
    
def add_iv(nums, iv):
    ivec = conv_to_num(iv)
    for x in range(len(ivec)):
        nums[x] = (nums[x] + ivec[x]) % 26
    return nums
    
def sub_iv(nums, iv):
    ivec = conv_to_num(iv)
    for x in range(len(ivec)):
        nums[x] = (nums[x] - ivec[x]) % 26
    return nums
    
def add_cbc(nums, b):
    for x in range(len(b)):
        nums[x] = (nums[x] + b[x]) % 26
    return nums
    
def sub_cbc(nums, b):
    for x in range(len(b)):
        nums[x] = (nums[x] - b[x]) % 26
    return nums
    
def key_scheduler(sbox, key, block_len):
    keys = []
    n = conv_to_num(key)
    k = list(n)
    n = sub_text(sbox, n)
    n = add_layerA(n, block_len)
    n = transpose(n, block_len)
    n = add_layerB(n, block_len)
    n = add_key(n, k)
    keys.append(n)
    
    n = sub_text(sbox, n)
    n = add_layerA(n, block_len)
    n = transpose(n, block_len)
    n = add_layerB(n, block_len)
    n = add_key(n, keys[0])
    keys.append(n)
    
    n = sub_text(sbox, n)
    n = add_layerA(n, block_len)
    n = transpose(n, block_len)
    n = add_layerB(n, block_len)
    n = add_key(n, keys[1])
    keys.append(n)
    return keys

def cipher_fw(s0, text, key, iv, block_len):
    rounds = 3

    k = conv_to_num(key)
    sbox = conv_to_num(s0)
    keys = key_scheduler(sbox, key, block_len)
    ctxt = []
    last = []
    blocks = len(text) // block_len
    c = 0
    for x in range(blocks):
        tbite = text[c:c+block_len]
        n = conv_to_num(tbite)
        if x == 0:
            n = add_iv(n, iv)
        else:
            n = add_cbc(n, last)
        for r in range(rounds):
            n = sub_text(sbox, n)
            n = add_layerA(n, block_len)
            n = transpose(n, block_len)
            n = add_layerB(n, block_len)
            n = add_key(n, keys[r])
        for y in n:
            ctxt.append(y)
        last = list(n)
        c += block_len
    t = conv_to_letters(ctxt)
    return t
    
def cipher_rev(s0, text, key, iv, block_len):
    rounds = 3
    k = conv_to_num(key)
    sbox = conv_to_num(s0)
    keys = key_scheduler(sbox, key, block_len)
    ptxt = []
    last = []
    blocks = len(text) // block_len
    c = 0
    for x in range(blocks):
        tbite = text[c:c+block_len]
        n = conv_to_num(tbite)
        last = list(n)
        for r in reversed(range(rounds)):
            n = sub_key(n, keys[r])
            n = sub_layerB(n, block_len)
            n = transpose_rev(n, block_len)
            n = sub_layerA(n, block_len)
            n = sub_text_rev(sbox, n)
    
        if x == 0:
            n = sub_iv(n, iv)
        else:
            n = sub_cbc(n, next)
        next = last
        for y in n:
            ptxt.append(y)
        c += block_len
    t = conv_to_letters(ptxt)
    return t

iv = "IAGMLABD"
key = "UHENAUST"
#text = "AAAAAAAA"
m = [chr(65)] * 100000
msg = "".join(m)
ctxt = cipher_fw(s0, msg, key, iv, 8)
print(ctxt)
#ptxt = cipher_rev(s0, ctxt, key, iv, 8)
#print(ptxt)
