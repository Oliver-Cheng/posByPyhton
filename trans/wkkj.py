#!/usr/bin/python
#coding:gbk
'''
1. 密钥全部配置明文
2. 在交易的配置中所需的域都要配置，2、11、35、36、41、42、64有默认值，这些域才会自动赋值。
3. 关联域配置形如[-1, lambda x:x.req.fields['F011'].value]
-1是关联的交易的索引，标识取前面第一个交易，-2标识取前面第二个交易；
lambda表达式标识域内容，x标识交易本身，req，resp标识请求还是应答，fields['F011'].value取域的内容
'''


mac_mode = 'CBC'

term_id = '99999999'
mchnt_id = '103290070111234'
#term_id = '98690001'
#mchnt_id = '898430170110369'

card_no = '6224243000000011'
pin = '123456'
track2 = '6225882116400091D0509567890123456'
track3 = '996225882116400091D1561560000000000000003976999236000002070000000000000000000000D000000000000D00'




qiandao = {
    'name' : '签到',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0800',
    'F011' : '000001',
    'F041' : '11115005',
    'F042' : '123456789111115',
    'F060' : '00000001003',
    'F063' : '001'.encode('hex'),
}

qudaochaxun = {
    'name' : '渠道查询',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0100',
    'F002' : '4761739001010176',
    'F003' : '380000',
    'F011' : '000001',
    'F022' : '012',
    'F025' : '87',
    'F041' : '11115005',
    'F042' : '123456789111115',
	'F048' : ('TAAABB00000001'+''.rjust(50)+'000000'+'NOCARD'.ljust(10)+'01'+''.ljust(40)+'898330572300006'.ljust(15)+'#').encode('HEX'),
    'F060' : '00000001000',
    'F064' : '1234567890ABCDEF',
}

zhifuzhunbei = {
    'name' : '支付准备',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0100',
    'F002' : '4761739001010176',
    'F003' : '330000',
	'F004' : '1',
    'F011' : '000001',
    'F022' : '012',
    'F025' : '94',
    'F041' : '11115005',
    'F042' : '123456789111115',
	'F048' : ('ZBAABB00000001'+''.rjust(50)+'000000'+'#').encode('HEX'),
    'F049' : '156',
    'F060' : '00000001000',
    'F062' : ('IRPC'+'004'+'WKKJ').encode('HEX'),
    'F064' : '1234567890ABCDEF',
}

#触发短信48域附加域
name  = 'com'
phone = '13222222222'
cert_no = '310115197803261111'
f48_addn = '1F0106'+'100001'.encode('HEX')+'1F0303'+name.encode('HEX')+'1F04023031' +'1F0512'+cert_no.encode('HEX')+'1F060B'+phone.encode('HEX')+'1F0210'+card_no.encode('HEX')

chufaduanxin = {
    'name' : '触发短信',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    'F002' : '4761739001010176',
    'F003' : '190000',
	'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '012',
    'F025' : '81',
    'F041' : '11115005',
    'F042' : '123456789111115',
	'F048' : ('CKZP1200000001').encode('HEX')+str(len(f48_addn)).rjust(3,'0').encode('HEX')+f48_addn+'#'.encode('HEX'),
    'F049' : '156',
    'F060' : '00000001000',
    'F064' : '1234567890ABCDEF',
}

zhifu = {
    'name' : '无卡支付',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    #'F002' : '4761739001010176',
    'F002' : [-1, lambda x: x.req.fields['F002'].value],
    'F003' : '190000',
	'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '012',
    'F025' : '82',
    'F041' : '11115005',
    'F042' : '123456789111115',
	'F048' : ('PAZP010000ZP02' +''.rjust(50)+'000000'+'288'+ '55A1'+'0000'+'ZP01'+''.rjust(32)+''.rjust(12)+'1234567'.rjust(32)+''.rjust(200)+'#').encode('HEX'),
    'F049' : '156',
    'F060' : '00000001000',
    #'F062' : [-1, lambda x : (x.resp.fields['F048'].value)[140:180]],
    'F062' : [-1, lambda x : ('IRPS012').encode('HEX') +x.resp.fields['F048'].value[140:180].decode('HEX').strip().encode('HEX')],
    'F064' : '1234567890ABCDEF',
}


all_trans = [
    qiandao, 
	qudaochaxun,
	#chufaduanxin,
	#zhifuzhunbei,
	#zhifu,
]
