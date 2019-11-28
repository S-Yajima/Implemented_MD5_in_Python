'''
MD5のアルゴリズムをPythonで再現してみました。
IPAのサイトに掲載されているRFCのメモを参考にしています。
https://www.ipa.go.jp/security/rfc/RFC1321JA.html
関数名、変数名も極力メモ中の名称を採用しています。
'''

S11, S12, S13, S14 = 7, 12, 17, 22
S21, S22, S23, S24 = 5, 9, 14, 20
S31, S32, S33, S34 = 4, 11, 16, 23
S41, S42, S43, S44 = 6, 10, 15, 21

PADDING = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]

# MD5 context. #
class MD5_CTX:
    state = [0x00000000]*4
    count = [0x00000000]*2
    buffer = [0x00]*64

    # MD5Init
    def __init__(self):
        self.count[0] = 0x00000000
        self.count[1] = 0x00000000
        self.state[0] = 0x67452301
        self.state[1] = 0xefcdab89
        self.state[2] = 0x98badcfe
        self.state[3] = 0x10325476

# MD5 basic transformation.Transforms state based on block.
# UINT4 state[4];
# unsigned char block[64];
def MD5Transform (state, block):
    x = [0x00000000] * 16
    a, b, c, d = state[0], state[1], state[2], state[3]

    Decode(x, block, 16)

    # Round 1
    a = FF(a, b, c, d, x[0], S11, 0xd76aa478)  # 1
    d = FF(d, a, b, c, x[1], S12, 0xe8c7b756)  # 2
    c = FF(c, d, a, b, x[2], S13, 0x242070db)  # 3
    b = FF(b, c, d, a, x[3], S14, 0xc1bdceee)  # 4
    a = FF(a, b, c, d, x[4], S11, 0xf57c0faf)  # 5
    d = FF(d, a, b, c, x[5], S12, 0x4787c62a)  # 6
    c = FF(c, d, a, b, x[6], S13, 0xa8304613)  # 7
    b = FF(b, c, d, a, x[7], S14, 0xfd469501)  # 8
    a = FF(a, b, c, d, x[8], S11, 0x698098d8)  # 9
    d = FF(d, a, b, c, x[9], S12, 0x8b44f7af)  # 10
    c = FF(c, d, a, b, x[10], S13, 0xffff5bb1)  # 11
    b = FF(b, c, d, a, x[11], S14, 0x895cd7be)  # 12
    a = FF(a, b, c, d, x[12], S11, 0x6b901122)  # 13
    d = FF(d, a, b, c, x[13], S12, 0xfd987193)  # 14
    c = FF(c, d, a, b, x[14], S13, 0xa679438e)  # 15
    b = FF(b, c, d, a, x[15], S14, 0x49b40821)  # 16

    # Round 2
    a = GG (a, b, c, d, x[1],  S21, 0xf61e2562) # 17
    d = GG (d, a, b, c, x[6],  S22, 0xc040b340) # 18
    c = GG (c, d, a, b, x[11], S23, 0x265e5a51) # 19
    b = GG (b, c, d, a, x[0],  S24, 0xe9b6c7aa) # 20
    a = GG (a, b, c, d, x[5],  S21, 0xd62f105d) # 21
    d = GG (d, a, b, c, x[10], S22, 0x02441453) # 22
    c = GG (c, d, a, b, x[15], S23, 0xd8a1e681) # 23
    b = GG (b, c, d, a, x[4],  S24, 0xe7d3fbc8) # 24
    a = GG (a, b, c, d, x[9],  S21, 0x21e1cde6) # 25
    d = GG (d, a, b, c, x[14], S22, 0xc33707d6) # 26
    c = GG (c, d, a, b, x[3],  S23, 0xf4d50d87) # 27
    b = GG (b, c, d, a, x[8],  S24, 0x455a14ed) # 28
    a = GG (a, b, c, d, x[13], S21, 0xa9e3e905) # 29
    d = GG (d, a, b, c, x[2],  S22, 0xfcefa3f8) # 30
    c = GG (c, d, a, b, x[7],  S23, 0x676f02d9) # 31
    b = GG (b, c, d, a, x[12], S24, 0x8d2a4c8a) # 32

    # Round 3
    a = HH (a, b, c, d, x[5],  S31, 0xfffa3942) # 33
    d = HH (d, a, b, c, x[8],  S32, 0x8771f681) # 34
    c = HH (c, d, a, b, x[11], S33, 0x6d9d6122) # 35
    b = HH (b, c, d, a, x[14], S34, 0xfde5380c) # 36
    a = HH (a, b, c, d, x[1],  S31, 0xa4beea44) # 37
    d = HH (d, a, b, c, x[4],  S32, 0x4bdecfa9) # 38
    c = HH (c, d, a, b, x[7],  S33, 0xf6bb4b60) # 39
    b = HH (b, c, d, a, x[10], S34, 0xbebfbc70) # 40
    a = HH (a, b, c, d, x[13], S31, 0x289b7ec6) # 41
    d = HH (d, a, b, c, x[0],  S32, 0xeaa127fa) # 42
    c = HH (c, d, a, b, x[3],  S33, 0xd4ef3085) # 43
    b = HH (b, c, d, a, x[6],  S34, 0x04881d05) # 44
    a = HH (a, b, c, d, x[9],  S31, 0xd9d4d039) # 45
    d = HH (d, a, b, c, x[12], S32, 0xe6db99e5) # 46
    c = HH (c, d, a, b, x[15], S33, 0x1fa27cf8) # 47
    b = HH (b, c, d, a, x[2],  S34, 0xc4ac5665) # 48

    # Round 4
    a = II (a, b, c, d, x[0],  S41, 0xf4292244) # 49
    d = II (d, a, b, c, x[7],  S42, 0x432aff97) # 50
    c = II (c, d, a, b, x[14], S43, 0xab9423a7) # 51
    b = II (b, c, d, a, x[5],  S44, 0xfc93a039) # 52
    a = II (a, b, c, d, x[12], S41, 0x655b59c3) # 53
    d = II (d, a, b, c, x[3],  S42, 0x8f0ccc92) # 54
    c = II (c, d, a, b, x[10], S43, 0xffeff47d) # 55
    b = II (b, c, d, a, x[1],  S44, 0x85845dd1) # 56
    a = II (a, b, c, d, x[8],  S41, 0x6fa87e4f) # 57
    d = II (d, a, b, c, x[15], S42, 0xfe2ce6e0) # 58
    c = II (c, d, a, b, x[6],  S43, 0xa3014314) # 59
    b = II (b, c, d, a, x[13], S44, 0x4e0811a1) # 60
    a = II (a, b, c, d, x[4],  S41, 0xf7537e82) # 61
    d = II (d, a, b, c, x[11], S42, 0xbd3af235) # 62
    c = II (c, d, a, b, x[2],  S43, 0x2ad7d2bb) # 63
    b = II (b, c, d, a, x[9],  S44, 0xeb86d391) # 64

    state[0] = (state[0] + a) & 0xffffffff
    state[1] = (state[1] + b) & 0xffffffff
    state[2] = (state[2] + c) & 0xffffffff
    state[3] = (state[3] + d) & 0xffffffff

    MD5_memset(x, 0, 16)    # 16 = x 要素数

# MD5_CTX * context;     / *context* /
# unsigned char * input; / *input block* /
# unsigned int inputLen; / *length of input block* /
def MD5Update (context, input, inputLen):
    #/* Compute number of bytes mod 64 */
    index = ((context.count[0] >> 3) & 0x3F)
    #/ *Update number of bits * /
    context.count[0] += (inputLen << 3)
    if (context.count[0] < (inputLen << 3)):
        context.count[1] =+ 1
    context.count[1] =+ (inputLen  >> 29)

    partLen = 64 - index

    #/* Transform as many times as possible.*/
    if (inputLen >= partLen):
        for j in range(partLen):
            context.buffer[index + j] = input[j]
        MD5Transform (context.state, context.buffer)
        for i in range (partLen, inputLen - 63, 64):
            MD5Transform (context.state, input[i])
        index = 0
    else:
        i = 0
        #/ *Buffer remaining input * /
        for j in range(inputLen - i):
            context.buffer[index + j] = input[j]

# unsigned char digest[16]; / *message digest * /
# MD5_CTX * context;        / *context * /
def  MD5Final (digest, context):
    bits = [0] * 8
    #/ *Save number of bits * /
    Encode(bits, context.count, 2)
    # / *Pad out to 56 mod 64 * /
    index = ((context.count[0] >> 3) & 0x3f)
    padLen = (56 - index) if (index < 56) else (120 - index)
    MD5Update(context, PADDING, padLen)
    #/ *Append length(before padding) * /
    MD5Update(context, bits, 8)
    # / *Store state in digest * /
    Encode(digest, context.state, 4)
    # / *Zeroize sensitive information.* /
    #MD5_memset(context, 0, sizeof(*context));


# 32 ビットワード 3つを入力とし、
# 32 ビットワード 1つを出力する 4つの補助関数を定義する。
# F(X,Y,Z) = XY v not(X) Z
def F(x, y, z):
    return ((x & y) | (~x & z)) & 0xffffffff
# G(X,Y,Z) = XZ v Y not(Z)
def G(x, y, z):
    return ((x & z) | (y & ~z)) & 0xffffffff
# H(X,Y,Z) = X xor Y xor Z
def H(x, y, z):
    return (x ^ y ^ z) & 0xffffffff
# I(X,Y,Z) = Y xor (X v not(Z))
def I(x, y, z):
    return (y ^ (x | ~z)) & 0xffffffff

def ROTATE_LEFT(x, n):
    return ((x << n) | (x >> (32 - n)))

def FF(a, b, c, d, x, s, ac):
    a = (a + F(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

def GG(a, b, c, d, x, s, ac):
    a = (a + G(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

def HH(a, b, c, d, x, s, ac):
    a = (a + H(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT (a, s)
    a = (a + b) & 0xffffffff
    return a

def II(a, b, c, d, x, s, ac):
    a = (a + I(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT (a, s)
    a = (a + b) & 0xffffffff
    return a

def MD5_memcpy(output, input, len):
    for i in range(len):
        output[i] = input[i]

def MD5_memset(output, value, len):
    for i in range(len):
        output[i] = value

# Decodes input (unsigned char) into output (UINT4).
# Assumes len is a multiple of 4.
def Decode (output, input, len):
    for i in range(len):
        output[i] = input[i * 4] | \
                    input[i * 4 + 1] << 8 | \
                    input[i * 4 + 2] << 16 | \
                    input[i * 4 + 3] << 24

# Encodes input (UINT4) into output (unsigned char).
# Assumes len is a multiple of 4.
def Encode(output, input, len):
    for i in range(len):
        output[i * 4] = input[i] & 0x000000ff
        output[i * 4 + 1] = input[i] >> 8 & 0x000000ff
        output[i * 4 + 2] = input[i] >> 16 & 0x000000ff
        output[i * 4 + 3] = input[i] >> 24 & 0x000000ff

def MDPring(digest):
    print('%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x'%( \
        digest[0],digest[1],digest[2],digest[3],digest[4],digest[5],digest[6],digest[7], \
        digest[8],digest[9],digest[10],digest[11],digest[12],digest[13],digest[14],digest[15]))

# /* Digests a string and prints the result.
# char *string;
def MDString(string):
    context = MD5_CTX()
    digest = [0] * 16
    length = len(string)

    MD5Update(context, string, length)
    MD5Final(digest, context)
    MDPring(digest)


if __name__ == '__main__':
    #enc = 'utf-8'
    enc = 'shift-jis'
    message = 'あいうえお'.encode(enc)
    message_ord_list = []

    for c in message:
        message_ord_list.append(c)

    MDString(message_ord_list)

    # 'ABCDE' の場合
    # > 2e:cd:de:39:59:05:1d:91:3f:61:b1:45:79:ea:13:6d
    # 'あいうえお'(shift-jis) の場合
    # > ad:7c:f5:ce:53:13:f8:b3:fc:59:d6:26:b9:aa:d6:53
