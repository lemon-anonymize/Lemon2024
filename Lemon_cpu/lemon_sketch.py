
class Bitmap:
    def __init__(self, size = 256):
        self.sum = 0
        self.size = size
        self.bitmap = [0] * size

    def _hash(self, item):
        hash_object = hashlib.sha512(item.encode())
        hash_int = int(hash_object.hexdigest(), 16)
        return hash_int % self.size

    def add(self, item):
        index = self._hash(item)
        self.bitmap[index] = 1
        self.sum = self.sum + 1

    def count_0(self):
        sum_0 = 0
        for bit in self.bitmap:
            if bit == 0:
                sum_0 = sum_0 + 1
        return sum_0

    def count(self):
        m = self.size
        V = self.count_0()
        if V == 0:
            return m 
        ##print(V,len(self.bitmap),self.sum)
        return -m * (math.log(V / m))

class Lemon_sketch:
    def __init__(self, size1 = 524288, size2 = 65536, size3 = 8192, size4 = 2048, size5 = 1024):
        #size1 = 65536
        self.l1_bitmapsize = 8
        self.l2_bitmapsize = 32
        self.l3_bitmapsize = 32
        self.l4_bitmapsize = 32
        self.l5_bitmapsize = 512

        self.sample1 = 16384
        self.sample2 = 8192
        self.sample3 = 1024
        self.sample4 = 256

        self.counter = [0] * size1 #Non-essential

        self.layer1 = [Bitmap(self.l1_bitmapsize) for i in range(size1)]
        self.layer2 = [Bitmap(self.l2_bitmapsize) for i in range(size2)]
        self.layer3 = [Bitmap(self.l3_bitmapsize) for i in range(size3)]
        self.layer4 = [Bitmap(self.l4_bitmapsize) for i in range(size4)]
        self.layer5 = [Bitmap(self.l5_bitmapsize) for i in range(size5)]
        

        self.size1 = size1
        self.size2 = size2
        self.size3 = size3
        self.size4 = size4
        self.size5 = size5

    def insert(self, item_flow, item_pkg):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer1 = int(hash_object.hexdigest(), 16) % self.size1

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer2 = int(hash_object.hexdigest(), 16) % self.size2

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer3 = int(hash_object.hexdigest(), 16) % self.size3

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer4 = int(hash_object.hexdigest(), 16) % self.size4

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer5 = int(hash_object.hexdigest(), 16) % self.size5

        hash_object = hashlib.sha256(item_pkg.encode())
        hash_deep = int(hash_object.hexdigest(), 16) % 65536
        
        self.counter[hash_layer1] = self.counter[hash_layer1] + 1

        if hash_deep < self.sample4:
            self.layer5[hash_layer5].add(item_pkg)
        elif hash_deep < self.sample3:
            self.layer4[hash_layer4].add(item_pkg)
        elif hash_deep < self.sample2:
            self.layer3[hash_layer3].add(item_pkg)
        elif hash_deep < self.sample1:
            self.layer2[hash_layer2].add(item_pkg)
        else:
            self.layer1[hash_layer1].add(item_pkg)

    def query(self, item_flow):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer1 = int(hash_object.hexdigest(), 16) % self.size1

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer2 = int(hash_object.hexdigest(), 16) % self.size2

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer3 = int(hash_object.hexdigest(), 16) % self.size3

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer4 = int(hash_object.hexdigest(), 16) % self.size4

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer5 = int(hash_object.hexdigest(), 16) % self.size5

        l1_count_0 = self.layer1[hash_layer1].count_0()
        l2_count_0 = self.layer2[hash_layer2].count_0()
        l3_count_0 = self.layer3[hash_layer3].count_0()
        l4_count_0 = self.layer4[hash_layer4].count_0()
        l5_count_0 = self.layer5[hash_layer5].count_0()

        est1 = self.layer1[hash_layer1].count() + self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = max(self.layer1[hash_layer1].count() * 65536/(65536 - self.sample1),1)
        est_layer1 = min(est1,est2)

        est1 = self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer2[hash_layer2].count() * 65536/(65536 - self.sample2) * (65536/self.sample1)
        est1 *= (65536/self.sample1)
        est_layer2 = min(est1,est2)

        est1 = self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer3[hash_layer3].count() * 65536/(65536 - self.sample3) * (65536/self.sample2)
        est1 *= (65536/self.sample2)
        est_layer3 = min(est1,est2)

        est1 = self.layer4[hash_layer4].count() + self.layer5[hash_layer5].count() 
        est2 = self.layer4[hash_layer4].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
        est1 *= (65536/self.sample3)
        est_layer4 = min(est1,est2)
    
        layertag = 0
        if l1_count_0 > self.l1_bitmapsize/5:
            return est_layer1#max(1,min(est1,est2))
        elif l2_count_0 > self.l2_bitmapsize/5:
            for i in range(0, int(self.size1/self.size2)):
                elimi_hash = hash_layer1 % self.size2 + i*self.size2
                if elimi_hash == hash_layer1:
                    continue
                est_layer2 -= self.layer1[elimi_hash].count() * 65536/(65536 - self.sample1)
            return est_layer2
        elif l3_count_0 > self.l3_bitmapsize/5:
            for i in range(0, int(self.size2/self.size3)):
                elimi_hash = hash_layer2 % self.size3 + i*self.size3
                if elimi_hash == hash_layer2:
                    continue
                est_layer3 -= self.layer2[elimi_hash].count()  * 65536/(65536 - self.sample2) * (65536/self.sample1)
            return est_layer3
        elif l4_count_0 > self.l4_bitmapsize/5:
            for i in range(0, int(self.size3/self.size4)):
                elimi_hash = hash_layer4 % self.size4 + i*self.size4
                if elimi_hash == hash_layer3:
                    continue
                est_layer4 -= self.layer3[elimi_hash].count()   * 65536/(65536 - self.sample3) * (65536/self.sample2)
            return est_layer4
        else:
            est_layer5 = (self.layer5[hash_layer5].count() * (65536/self.sample4))
            for i in range(0, int(self.size4/self.size5)):
                elimi_hash = hash_layer4 % self.size5 + i*self.size5
                if elimi_hash == hash_layer4:
                    continue
                est_layer5 -= self.layer4[elimi_hash].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
            return est_layer5

    def query_hash(self, hashnum):
        hash_layer1 = hashnum % self.size1
        hash_layer2 = hashnum % self.size2
        hash_layer3 = hashnum % self.size3
        hash_layer4 = hashnum % self.size4
        hash_layer5 = hashnum % self.size5

        l1_count_0 = self.layer1[hash_layer1].count_0()
        l2_count_0 = self.layer2[hash_layer2].count_0()
        l3_count_0 = self.layer3[hash_layer3].count_0()
        l4_count_0 = self.layer4[hash_layer4].count_0()
        l5_count_0 = self.layer5[hash_layer5].count_0()

        est1 = self.layer1[hash_layer1].count() + self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = max(self.layer1[hash_layer1].count() * 65536/(65536 - self.sample1),1)
        est_layer1 = min(est1,est2)

        est1 = self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer2[hash_layer2].count() * 65536/(65536 - self.sample2) * (65536/self.sample1)
        est1 *= (65536/self.sample1)
        est_layer2 = min(est1,est2)

        est1 = self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer3[hash_layer3].count() * 65536/(65536 - self.sample3) * (65536/self.sample2)
        est1 *= (65536/self.sample2)
        est_layer3 = min(est1,est2)

        est1 = self.layer4[hash_layer4].count() + self.layer5[hash_layer5].count() 
        est2 = self.layer4[hash_layer4].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
        est1 *= (65536/self.sample3)
        est_layer4 = min(est1,est2)
    
        layertag = 0
        if l1_count_0 > self.l1_bitmapsize/5:
            return est_layer1#max(1,min(est1,est2))
        elif l2_count_0 > self.l2_bitmapsize/5:
            for i in range(0, int(self.size1/self.size2)):
                elimi_hash = hash_layer1 % self.size2 + i*self.size2
                if elimi_hash == hash_layer1:
                    continue
                est_layer2 -= self.layer1[elimi_hash].count() * 65536/(65536 - self.sample1)
            return est_layer2
        elif l3_count_0 > self.l3_bitmapsize/5:
            for i in range(0, int(self.size2/self.size3)):
                elimi_hash = hash_layer2 % self.size3 + i*self.size3
                if elimi_hash == hash_layer2:
                    continue
                est_layer3 -= self.layer2[elimi_hash].count()  * 65536/(65536 - self.sample2) * (65536/self.sample1)
            return est_layer3
        elif l4_count_0 > self.l4_bitmapsize/5:
            for i in range(0, int(self.size3/self.size4)):
                elimi_hash = hash_layer4 % self.size4 + i*self.size4
                if elimi_hash == hash_layer3:
                    continue
                est_layer4 -= self.layer3[elimi_hash].count()   * 65536/(65536 - self.sample3) * (65536/self.sample2)
            return est_layer4
        else:
            est_layer5 = (self.layer5[hash_layer5].count() * (65536/self.sample4))
            for i in range(0, int(self.size4/self.size5)):
                elimi_hash = hash_layer4 % self.size5 + i*self.size5
                if elimi_hash == hash_layer4:
                    continue
                est_layer5 -= self.layer4[elimi_hash].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
            return est_layer5


    def counter_query(self, item_flow):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.size1
        l_count_0 = self.counter[hash_int]
        return l_count_0
