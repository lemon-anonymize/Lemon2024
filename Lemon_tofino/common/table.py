import logging

class Table(object):
    def __init__(self, target, gc, bfrt_info, table_name):
        self.log = logging.getLogger(__name__)
        self.target = target
        self.table_name = "SwitchIngress.%s"%table_name
        self.gc = gc

        self.table = bfrt_info.table_get(table_name)
        self.mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        self.entry = []
        self.mirror_session_id = []

    def readTable_tbl(self):
        # 如果带寄存器的话Apply table operations to sync the direct registers
        # target_table.operations_execute(self.target, 'SyncRegisters')

        resp = self.table.entry_get(self.target, None, {"from_hw": True})#read all entry in table
        resp2 = self.table.entry_get(self.target, None, {"from_hw": True})
        length = len(list(resp2))
        print("\nR---->Table: %s, %d entry"%(self.table_name,length))
        for data,key in resp:
            print(key)
            print(data)
        print()

    def readTable_reg(self):
        #"Syncing indirect stful registers"
        self.table.operations_execute(self.target, 'Sync')

        resp = self.table.entry_get(self.target, None, {"from_hw": False})#read all entry in table
        resp2 = self.table.entry_get(self.target, None, {"from_hw": False})
        length = len(list(resp2))
        print("\nR---->Register: %s, %d entry"%(self.table_name,length))
        for data,key in resp:
            print(key)
            print(data)
        print()

    def clearEntry(self):
        self.table.entry_del(self.target)
        self.entry = []
        self.log.info('Clear entry of table: {}'.format(self.table_name))
        print("\nC---->Table %s is empty now!"%self.table_name)
    
    def initRegister(self,value=0,reg_field="f1"):
        resp2 = self.table.entry_get(self.target, None, {"from_hw": False})
        length = len(list(resp2))
        for i in range(length):
            self.writeRegister(i,value,reg_field)
        self.log.info('Init register {}(length: {}) all to 0'.format(self.table_name,length))
        print("\nW---->Init register {}(length: {}) all to 0:".format(self.table_name,length))

    def writeRegister(self,index,value,reg_field="f1"):
        resp = self.table.entry_mod(
            self.target,
            [self.table.make_key([self.gc.KeyTuple('$REGISTER_INDEX', index)])],
            [self.table.make_data([self.gc.DataTuple('%s.%s'%(self.table_name,reg_field), value)])]
            )

    def readRegister(self,index,reg_field="f1", silence=False):
        resp = self.table.entry_get(
            self.target,
            [self.table.make_key([self.gc.KeyTuple('$REGISTER_INDEX', index)])],
            {"from_hw": True}
            )
        data_dict = next(resp)[0].to_dict()
        if(silence == False):
            a=1
            #print(data_dict["%s.%s"%(self.table_name,reg_field)][1], end='\t')
        return data_dict["%s.%s"%(self.table_name,reg_field)][1]
    
    def readDirectRegister(self,match_type,key):
        key_list = self.__getKeyList__(match_type,key)
        resp = register_dir_table.entry_get(
            self.target,
            key_list,
            {"from_hw": True})
        data_dict = next(resp)[0].to_dict()
        print(data_dict["%s.f1"%self.table_name][1], end='\t')

    def key_field_annotation_add(keys):
        for key, alias in keys:
            self.table.info.key_field_annotation_add(key, alias)
            
    def __getKeyList__(self,match_type,keys):
        entry_keys = []
        for key in keys:
                if(match_type == "exact"):
                    # self.table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
                    # self.table.info.key_field_annotation_add("hdr.ipv4.protocol", "bytes")
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1]))
                elif(match_type == "lpm"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1],prefix_len=key[2]))
                elif(match_type == "ternary"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1],key[2]))
                elif(match_type == "range"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr[15:0]", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0], low=key[1],high=key[2]))
                elif(match_type == "exact-none"):
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1]))
        key_list = [self.table.make_key(entry_keys)]
        return key_list

    def addEntry(self,match_type,keys,action,action_parameter):

        if(self.entry.count(keys) == 1):
            print("Entry already exist, won't insert twice!")
            self.log.info("%s :Entry already exist, won't insert twice!"%self.table_name)
        else:           
            key_list = self.__getKeyList__(match_type,keys)
            entry_data = []
            for parameter in action_parameter:
                entry_data.append(self.gc.DataTuple(parameter[0],parameter[1]))
            action = "SwitchIngress.%s"%action
            data_list = [self.table.make_data(entry_data,action)]
            try:
                resp = self.table.entry_get(self.target,key_list,{"from_hw": True})
                data_dict = next(resp)[0].to_dict()
            except:
                print("\nA---->Add entry(%s): %s %s(%s)"%(match_type,keys,action,action_parameter))
                self.table.entry_add(self.target, key_list, data_list)
                self.log.info("Added entry success: %s"%self.table_name)
                self.entry.append(keys)
            else:
                print("Entry already exist in %s, won't insert twice!"%self.table_name)
                self.log.info("Added entry failed :%s Entry already exist, won't insert twice!"%self.table_name)

    def config_mirror(self,sid,port):

        # self.mirror_cfg_table.entry_del(
        #         self.target,
        #         [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])])
        try:
            resp = self.mirror_cfg_table.entry_get(
                self.target,
                [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])],
                {"from_hw": True},
                self.mirror_cfg_table.make_data([self.gc.DataTuple('$direction'),
                                            self.gc.DataTuple('$ucast_egress_port'),
                                            self.gc.DataTuple('$ucast_egress_port_valid'),
                                            self.gc.DataTuple('$session_enable')],
                                            '$normal')
            )
            data_dict = next(resp)[0].to_dict()
        except:
            self.mirror_cfg_table.entry_add(
                    self.target,
                    [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])],
                    [self.mirror_cfg_table.make_data([self.gc.DataTuple('$direction', str_val="INGRESS"),
                                                    self.gc.DataTuple('$ucast_egress_port', port),
                                                    self.gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                    self.gc.DataTuple('$session_enable', bool_val=True)],
                                                '$normal')]
                )
            self.log.info("Configure mirror success: %d"%sid)
        else:
            print("\n!!! Mirror session has been enable, won't set twice.")
            self.log.info("Configure mirror failed: Mirror session %d has been enable, won't set twice"%sid)
        resp = self.mirror_cfg_table.entry_get(self.target, None, {"from_hw": True})#read all entry in mirror_cfg_table
        resp2 = self.mirror_cfg_table.entry_get(self.target, None, {"from_hw": True})
        length = len(list(resp2))
        print("\nR---->Table: %s, %d entry"%("$mirror.cfg",length))
        for data,key in resp:
            print(key)
            print(data)
        print()