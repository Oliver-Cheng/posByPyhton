#!/usr/bin/python
#coding:gbk
'''
1. ��Կȫ����������
2. �ڽ��׵��������������Ҫ���ã�2��11��35��36��41��42��64��Ĭ��ֵ����Щ��Ż��Զ���ֵ��
3. ��������������[-1, lambda x:x.req.fields['F011'].value]
-1�ǹ����Ľ��׵���������ʶȡǰ���һ�����ף�-2��ʶȡǰ��ڶ������ף�
lambda���ʽ��ʶ�����ݣ�x��ʶ���ױ���req��resp��ʶ������Ӧ��fields['F011'].valueȡ�������
'''

host = ('144.131.254.154', 30202)


qiandao = {
    'name' : 'ǩ��',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0800',
    'F011' : '000001',
    'F041' : '11115005',
    'F042' : '123456789111115',
    'F060' : '00000001003',
    'F063' : '001'.encode('hex'),
}


zhanghuyanzheng = {
    'name' : '�˻���֤',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0100',
    'F002' : '4761739001010176',
    'F003' : '330000',
    'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '022',
    'F025' : '00',
    'F035' : '4761739001010176D140812100000502',
    'F041' : '11115005',
    'F042' : '123456789111115',
    'F049' : '156',
    'F060' : '0100002900050',
    'F064' : '1234567890ABCDEF',
}

xiaofei = {
    'name' : '����',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    'F002' : '4761739001010176',
    'F003' : '000000',
    'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '021',
    'F025' : '00',
    'F026' : '06',
    'F035' : '4761739001010176D140812100000502',
    'F041' : '11115005',
    'F042' : '123456789111115',
    'F049' : '156',
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '22000001000',
    'F064' : '1234567890ABCDEF',
}


xiaofeichongzheng = {
    'name' : '���ѳ���',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0400',
    'F002' : '4761739001010176',
    'F003' : [-1, lambda x : x.req.fields['F003'].value],
    'F004' : [-1, lambda x : x.req.fields['F004'].value],
    'F011' : [-1, lambda x : x.req.fields['F011'].value],
    'F022' : [-1, lambda x : x.req.fields['F022'].value],
    'F025' : [-1, lambda x : x.req.fields['F025'].value],
    #'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F039' : '00',
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F060' : [-1, lambda x : x.req.fields['F060'].value],
    'F064' : '1234567890ABCDEF',
}

xiaofeichexiao = {
    'name' : '���ѳ���',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    'F002' : [-1, lambda x : x.req.fields['F002'].value],
    'F003' : '200000',
    'F004' : [-1, lambda x : x.req.fields['F004'].value],
    'F011' : '000001',
    'F022' : '021',
    'F025' : '00',
    'F026' : '06',
    'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F037' : [-1, lambda x : x.resp.fields['F037'].value],
    'F038' : [-1, lambda x : x.resp.fields['F038'].value],
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '23000001000',
    'F061' : [-1, lambda x : x.req.fields['F060'].value[2:8] + x.req.fields['F011'].value],
    'F064' : '1234567890ABCDEF',
}

yushouquan = {
    'name' : 'Ԥ��Ȩ',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0100',
    'F002' : '4761739001010176',
    'F003' : '030000',
    'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '021',
    'F025' : '06',
    'F026' : '06',
    'F035' : '4761739001010176D140812100000502',
    'F041' : '11115005',
    'F042' : '123456789111115',
    'F049' : '156',
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '10000001000',
    'F064' : '1234567890ABCDEF',
}

yushouquanchexiao = {
    'name' : 'Ԥ��Ȩ����',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0100',
    'F002' : [-1, lambda x : x.req.fields['F002'].value],
    'F003' : '200000',
    'F004' : [-1, lambda x : x.req.fields['F004'].value],
    'F011' : '000001',
    'F022' : '021',
    'F025' : '06',
    'F026' : '06',
    'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F038' : [-1, lambda x : x.resp.fields['F038'].value],
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '11000001000',
    'F061' : [-1, lambda x : x.req.fields['F060'].value[2:8] + x.req.fields['F011'].value + x.resp.fields['F013'].value],
    'F064' : '1234567890ABCDEF',
}

yushouquanwancheng = {
    'name' : 'Ԥ��Ȩ���',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    'F002' : [-1, lambda x : x.req.fields['F002'].value],
    'F003' : '000000',
    'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '021',
    'F025' : '06',
    'F026' : '06',
    'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F038' : [-1, lambda x : x.resp.fields['F038'].value],
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '20000001000',
    'F061' : [-1, lambda x : x.req.fields['F060'].value[2:8] + x.req.fields['F011'].value + x.resp.fields['F013'].value],
    'F064' : '1234567890ABCDEF',
}


yushouquanwanchengchexiao = {
    'name' : 'Ԥ��Ȩ��ɳ���',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0200',
    'F002' : [-1, lambda x : x.req.fields['F002'].value],
    'F003' : '200000',
    'F004' : [-1, lambda x : x.req.fields['F004'].value],
    'F011' : '000001',
    'F022' : '021',
    'F025' : '06',
    'F026' : '06',
    'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F037' : [-1, lambda x : x.resp.fields['F037'].value],
    'F038' : [-1, lambda x : x.resp.fields['F038'].value],
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '21000001000',
    'F061' : [-1, lambda x : x.req.fields['F060'].value[2:8] + x.req.fields['F011'].value + x.resp.fields['F013'].value],
    'F064' : '1234567890ABCDEF',
}

def tuihuo_sleep(x):
    import time
    print 'sleep 30'
    time.sleep(30)
    return x.req.fields['F002'].value
    
tuihuo = {
    'name' : '�˻�',
    'tpdu' : '6000000000',
    'msg_head' : '602200000000',
    'msg_type' :'0220',
    'F002' : [-1, tuihuo_sleep],
    'F003' : '200000',
    'F004' : '000000000001',
    'F011' : '000001',
    'F022' : '021',
    'F025' : '00',
    'F026' : '06',
    'F035' : [-1, lambda x : x.req.fields['F035'].value],
    'F037' : [-1, lambda x : x.resp.fields['F037'].value],
    'F038' : [-1, lambda x : x.resp.fields['F038'].value],
    'F041' : [-1, lambda x : x.req.fields['F041'].value],
    'F042' : [-1, lambda x : x.req.fields['F042'].value],
    'F049' : [-1, lambda x : x.req.fields['F049'].value],
    'F052' : '111111',
    'F053' : '1600000000000000',
    'F060' : '25000001000',
    'F061' : [-1, lambda x : x.req.fields['F060'].value[2:8] + x.req.fields['F011'].value + x.resp.fields['F013'].value],
    'F063' : [-1, lambda x : x.resp.fields['F063'].value[:6]],
    'F064' : '1234567890ABCDEF',
}


all_trans = [
    qiandao, 
    #zhanghuyanzheng,
    #xiaofei, 
    #xiaofeichongzheng,
    #xiaofei, 
    #xiaofeichexiao,
    #yushouquan,
    #yushouquanchexiao,
    yushouquan,
    yushouquanwancheng,
    yushouquanwanchengchexiao,
    #xiaofei,
    #tuihuo,
]
