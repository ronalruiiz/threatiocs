from typing import Counter


class Ioc:
    def __init__(self,item,value,name="",type="",reputation="",detect="",country="",isp="", other_value=""):
        self.item = item
        self.value = value
        self.other_value = other_value
        self.name = name
        self.type = type
        self.reputation = reputation
        self.detection = detect
        self.country = country
        self.isp = isp

    def to_dict(self):
       return dict(item=self.item, value=self.value, name=self.name,type=self.type,
       reputation=self.reputation,detection=self.detection,country=self.country,isp=self.isp, other_value=self.other_value)

    def __str__(self):
        return "From str method of Test: %s, %s,%s, %s, %s, %s, %s" % (self.item, self.value,self.other_value,self.name,self.type,self.reputation,self.detection)
