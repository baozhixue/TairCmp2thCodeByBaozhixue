# TairCmp2thCodeByBaozhixue
  [第二届数据库大赛—Tair性能挑战](https://tianchi.aliyun.com/competition/entrance/531820/introduction)
  代码评分71.5s，排名18。
#总结：
    （1）程序在写入数据时，未能完全达到顺序写。在此部分使程序的性能有很大的降低。
    （2）未能很好地使用存储数据时的数据分布特性，对程序的性能可能具有致命一击。
    （3）在使用AEP时，未使用linux的API mmap可能使程序的性能有一定程度的下降。
