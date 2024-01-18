# check for multiple occurrences of same block (32 hexcharacters)

block_map = {}

with open("aes.data") as file:
    for line in file:
        for i in range(0, len(line), 32):
            block = str(line[i : i + 32])
            if block in block_map:
                print(line)
                # print(block)
            else:
                block_map[block] = 1

        block_map.clear()
          

