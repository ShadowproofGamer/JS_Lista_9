import re, abc

class IPv4Address:
    def __init__(self: "IPv4Address", raw:str) -> None:
        ipv4_pattern:str = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        data = re.search(ipv4_pattern, raw)
        if isinstance(data, re.Match):
            self.ip_addr:list[str] = data[0].split(".")
    def __str__(self: "IPv4Address") -> str:
        return "{}.{}.{}.{}".format(self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3])
    




    
class SSHTime:
    def __init__(self:"SSHTime", other:str) -> None:
        t_m = re.search(r'^\w{3}', other)
        t_d = re.search(r'(?<=^\w{3} {1})\w*|(?<=^\w{3} {2})\w*', other)
        t_h = re.search(r'(?<=^\w{3} {1}\w{2} )\w{2}|(?<=^\w{3} {2}\w )\w{2}', other)
        t_mi = re.search(r'(?<=^\w{3} {1}\w{2} \w{2}:)\w{2}|(?<=^\w{3} {2}\w \w{2}:)\w{2}', other)
        t_s = re.search(r'(?<=^\w{3} {1}\w{2} \w{2}:\w{2}:)\w{2}|(?<=^\w{3} {2}\w \w{2}:\w{2}:)\w{2}', other)
        if isinstance(t_m, re.Match):
            self.month:str = t_m.group(0)
        if isinstance(t_d, re.Match):
            self.day:str = t_d.group(0)
        if isinstance(t_h, re.Match):
            self.hour:str = t_h.group(0)
        if isinstance(t_mi, re.Match):
            self.minute:str = t_mi.group(0)
        if isinstance(t_s, re.Match):
            self.second:str = t_s.group(0)
    
    def __str__(self:"SSHTime") -> str:
        return "{} {} {}:{}:{}".format(self.month, self.day, self.hour, self.minute, self.second)
    
    def __eq__(self:"SSHTime", other:object) -> bool:
        if not isinstance(other, SSHTime):
            return NotImplemented
        else: return (self.month==other.month and self.day==other.day and self.hour==other.hour and self.minute==other.minute and self.second==other.second)
    
    


# z1, z3, z4

class SSHLogEntry(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(self, raw:str) -> None:
        t_t=re.search(r'^[A-Z][a-z]{2} {1,2}[0-9]{1,2} \w{2}:\w{2}:\w{2}', raw)
        t_h=re.search(r'(?<=:[0-9]{2} )\w*', raw)
        t_p=re.search(r'(?<=sshd\[)[0-9]*', raw)
        if isinstance(t_t, re.Match):
            self.time:SSHTime=SSHTime(t_t.group(0))
        if isinstance(t_h, re.Match):
            self.host_name:str=t_h.group(0)
        self._raw:str=raw
        if isinstance(t_p, re.Match):
            self.pid:int=int(t_p.group(0))
    
    @abc.abstractmethod
    def __str__(self) -> str:
        result:str = "{}\t\t{}\t\t{}\t\t{}".format(self.time,self.host_name,str(self.pid),self._raw)
        return result
    
    @abc.abstractmethod
    def get_ipv4(self) -> IPv4Address|None:
        return IPv4Address(self._raw)

    @abc.abstractmethod
    def validate(self) -> bool:
        date_pattern:str = r'^[A-Z][a-z]{2} {1,2}[0-9]{1,2} \w{2}:\w{2}:\w{2}'
        pid_pattern:str = r'(?<=\[)\w*(?=]:)'
        #print(str(self.time)==re.search(date_pattern, self._raw).group(0))
        t_d = re.search(date_pattern, self._raw)
        t_p = re.search(pid_pattern, self._raw)
        if isinstance(t_d, re.Match) and isinstance(t_p, re.Match):
            if(str(self.time)==t_d.group(0) and str(self.pid)==t_p.group(0)):
                return True
            else:
                return False
        else:
            return False
        
    # z5
    @property
    def has_ip(self) -> bool:
        if(self.get_ipv4()):
            return True
        else:
            return False
    
    # z6
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogEntry", self.time, self._raw, self.pid, self.host_name)

    def __eq__(self:"SSHLogEntry", other:object) -> bool:
        if not isinstance(other, SSHLogEntry): 
            return False
        else:
            return (self.pid==other.pid)

    def __gt__(self:"SSHLogEntry", other:object) -> bool:
        if not isinstance(other, SSHLogEntry): 
            return False
        else:
            return (self.pid>other.pid)
        
            

    def __lt__(self:"SSHLogEntry", other:object) -> bool:
        if not isinstance(other, SSHLogEntry): 
            return False
        else:
            return (self.pid<other.pid)
        

    # z2

class SSHLogFailed(SSHLogEntry):
    def __init__(self, raw:str) -> None:
        super().__init__(raw)
        t_u = re.search(r'(?<=user )\w+', raw)
        t_p = re.search(r'(?<=port )\w*', raw)
        if isinstance(t_u, re.Match):
            self.user:str = t_u.group(0)
        if isinstance(t_p, re.Match):
            self.port:int = int(t_p.group(0))
    def __str__(self) -> str:
        return super().__str__()+"\t\t{}\t\t{}".format(self.user, self.port)
    def get_ipv4(self) -> IPv4Address|None:
        return super().get_ipv4()
    def validate(self) -> bool:
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogFailed", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self: "SSHLogFailed", other:object) -> bool:
        return super().__lt__(other)
    def __eq__(self: "SSHLogFailed", other: object) -> bool:
        return super().__eq__(other)
    def __gt__(self: "SSHLogFailed", other: object) -> bool:
        return super().__gt__(other)

class SSHLogAccepted(SSHLogEntry):
    def __init__(self, raw:str) -> None:
        super().__init__(raw)
        t_u = re.search(r'(?<=Accepted password for )\w*', raw)
        t_p = re.search(r'(?<=port )\w*', raw)
        if isinstance(t_u, re.Match):
            self.user:str = t_u.group(0)
        if isinstance(t_p, re.Match):
            self.port:int = int(t_p.group(0))
    def __str__(self) -> str:
        return super().__str__()+"\t\t{}\t\t{}".format(self.user, self.port)
    def get_ipv4(self) -> IPv4Address|None:
        return super().get_ipv4()
    def validate(self) -> bool:
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogAccepted", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, other:object) -> bool:
        return super().__lt__(other)
    def __eq__(self, other:object) -> bool:
        return super().__eq__(other)
    def __gt__(self, other:object) -> bool:
        return super().__gt__(other)

class SSHLogError(SSHLogEntry):
    def __init__(self, raw:str, errno:int=0, errdsc:str="") -> None:
        super().__init__(raw)
        t_no = re.search(r'(?<=[0-9]: )[0-9]+', raw)
        t_dsc = re.search(r'(?<=[0-9]: ).*(?=. \[)', raw)
        if isinstance(t_no, re.Match):
            if errno!=0: self.errno = int(t_no.group(0))
        if isinstance(t_dsc, re.Match):
            if errdsc!="": self.errdsc = t_dsc.group(0)
        #self.errno=errno
        #self.errdsc=errdsc

    def __str__(self) -> str:
        return super().__str__()
    def get_ipv4(self) -> IPv4Address|None:
        return super().get_ipv4()
    def validate(self) -> bool:
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogError", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, other:object) -> bool:
        return super().__lt__(other)
    def __eq__(self, other:object) -> bool:
        return super().__eq__(other)
    def __gt__(self, other:object) -> bool:
        return super().__gt__(other)


class SSHLogOther(SSHLogEntry):
    def __init__(self, raw:str) -> None:
        super().__init__(raw)
    def __str__(self) -> str:
        return super().__str__()
    def get_ipv4(self) -> IPv4Address|None:
        return super().get_ipv4()
    def validate(self) -> bool:
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogOther", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, other:object) -> bool:
        return super().__lt__(other)
    def __eq__(self, other:object) -> bool:
        return super().__eq__(other)
    def __gt__(self, other:object) -> bool:
        return super().__gt__(other)
        
# z7
class SSHLogJournal:
    def __init__(self) -> None:
        self._logs:list[SSHLogEntry]=list()
    
    def __len__(self) -> int:
        return len(self._logs)
    
    def __iter__(self):
        yield from self._logs

    def __contains__(self, other:SSHLogEntry) -> bool:
        for i in self._logs:
            if(i==other):
                return True
        return False

    def append(self, _repr:str) -> None:
        type_pattern:str = r'(?<=<)[a-zA-Z]*(?=;)'
        raw_pattern:str = r'(?<=raw=).*(?=, pid)'
        #print(re.search(date_pattern, _repr))
        t_ty = re.search(type_pattern, _repr)
        if isinstance(t_ty, re.Match):
            temp_type:str = t_ty.group(0)
        t_r = re.search(raw_pattern, _repr)
        if isinstance(t_r, re.Match):
            temp_raw:str = t_r.group(0)
        #if(re.search(host_pattern, _repr)):temp_host = re.search(host_pattern, _repr).group(0)
        if temp_type=="SSHLogFailed":
            new_object1:SSHLogFailed = SSHLogFailed(temp_raw)
            if(new_object1.validate()):
                self._logs.append(new_object1)
        elif temp_type=="SSHLogAccepted":
            new_object2:SSHLogAccepted = SSHLogAccepted(temp_raw)
            if(new_object2.validate()):
                self._logs.append(new_object2)
        elif temp_type =="SSHLogError":
             new_object3:SSHLogError = SSHLogError(temp_raw)
             if(new_object3.validate()):
                self._logs.append(new_object3)
        
        
    
    def logs_by_ip(self, ip:str):
        temp_list:list = []
        for i in self._logs:
            if(i.get_ipv4()):
                if(str(i.get_ipv4())==ip):
                    temp_list.append(i)
        return temp_list





# z8
class SSHUser:
    def __init__(self, name:str, last_login:SSHTime) -> None:
        self.username:str=name
        self.last_login:SSHTime=last_login

    def validate(self) -> bool:
        validation_pattern:str = r'^[A-z_][A-z0-9_-]{0,31}$'
        if(re.match(validation_pattern, self.username)):
            return True
        else:
            return False
    

# demonstracja:
container = SSHLogJournal()
test1 = SSHLogError("Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
test2 = SSHLogFailed("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
test3 = SSHLogAccepted("Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2")
test4 = SSHUser("root", SSHTime("Jan  7 16:55:18"))
test5 = SSHLogError("Dec 10 09:12:40 LabSZ sshd[24497]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")

print(SSHTime("Dec 10 11:03:44"))
print(repr(test1))
print(test1)
print(test2)
#print(test2.validate())
print(test3)
print(test5)

container.append(repr(test1))
container.append(repr(test2))
container.append(repr(test3))
container.append(repr(test5))

print("\nwpisy po ip 103.99.0.122:\n", container.logs_by_ip("103.99.0.122"), "\n")

lista=[]
for i in container:
    lista.append(i)



lista.append(test4)



index=1
for i in lista:
    print("test"+str(index), i.validate())
    index+=1

