#!/usr/bin/python
#coding:UTF-8
#############################################################################
#                Copyright (C),2002-2012,China UMS Co.,Ltd.
#
# File name      : pos.py
# Author         : 
# Version        : 1.0
# Date           : 2018-02-05
# Description    : pos仿真终端
#                  
#
#
# Others         :
# History        :
#No.      Date          Author      Modification
#=====    ===========   =========   ==========================================
#1        2018-02-05                 Create  file
##############################################################################
import os
import sys
import time
import socket
import traceback
import logging
import datetime
import re
from collections import namedtuple

import pos_cfg
import pyDes

Msg = namedtuple('Msg', ['req', 'resp'])

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
LOG_PATH = os.path.join(BASE_PATH, 'log')
CONFIG_FILE = os.path.join(BASE_PATH, 'pos_cfg.py')
SSN_FILE = os.path.join(BASE_PATH, 'pos.ssn')

BUFFER_SIZE = 5000


def divide(strings, width):
    '''等分切割
    如2等分'12345678' -> ['12', '34', '56', '78']
    '''
    #import re
    #return re.findall(r'.{%d}' % width, strings)
    return [strings[x:x+width] for x in xrange(0, len(strings), width)]


def hexstr_to_bitstr(data):
    '''Turn the string data, into a str of bits (1, 0)'s
    '''
    data = [int(c, 16) for c in data]
    l = len(data) * 4
    result = ['0'] * l
    pos = 0
    for ch in data:
        i = 3
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = '1'
            else:
                result[pos] = '0'
            pos += 1
            i -= 1

    return ''.join(result)


def bitstr_to_hexstr(data):
    if len(data) % 4:
        return None

    substrs = divide(data, 4)
    hexstr = ''
    for substr in substrs:
        hexstr += '%01X' % int(substr, 2)
    
    return hexstr
    

def des_decrypt(key, data, mode = pyDes.ECB):
    if len(key) == 16:
        d = pyDes.des(key.decode('hex'), mode, '0000000000000000'.decode('hex'), pad='\0')        
    elif len(key) == 32:
        d = pyDes.triple_des(key.decode('hex'), mode, '0000000000000000'.decode('hex'), pad='\0')
    else:
        return None
    
    return d.decrypt(data.decode('hex')).encode('hex')
    
    
def xor(str1, str2):
    lens = len(str1)
    if lens != len(str2):
        return None
    return ''.join(['%X' % (int(str1[i],16) ^ int(str2[i],16)) for i in range(lens)])

    
def des_encrypt(key, data, mode = pyDes.ECB):
    if len(key) == 16:
        d = pyDes.des(key.decode('hex'), mode, '0000000000000000'.decode('hex'), pad='\0')        
    elif len(key) == 32:
        d = pyDes.triple_des(key.decode('hex'), mode, '0000000000000000'.decode('hex'), pad='\0')
    else:
        return None
    
    return d.encrypt(data.decode('hex')).encode('hex')
    
    
def get_logger(log_name = ''):
    if not log_name:
        log_name = os.path.basename(__file__).replace('.py', '')
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)
    
    today = datetime.datetime.now().strftime('%Y%m%d')
    path = LOG_PATH
    if not os.path.exists(path):
        os.makedirs(path)
    filename = os.path.join(path, log_name + '_%s.log' % today)
    
    fh = logging.FileHandler(filename)
    ch = logging.StreamHandler()
    
    fh.setLevel(logging.DEBUG)
    ch.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s|%(pathname)20s:%(lineno)04d|%(levelname)4s|%(message)s', \
        datefmt='%Y-%m-%d %H:%M:%S')
    
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger
    
logger = get_logger()


class Field8583(object):
    '''8583域定义
    '''
    FMT_N = 0
    FMT_ANS = 1
    FMT_BIT = 2
    FMT_Z = 3
    
    LEN_FIXED = 0
    LEN_VAR_2 = 2
    LEN_VAR_3 = 3
    
    pos_field_re = {
        'F049' : re.compile(r'\d{3}'),
        'F052' : re.compile(r'[0-9A-Fa-f]{16}'),
        'F053' : re.compile(r'[0-9]{3}0{13}'),
        'F060' : re.compile(r'\d{2,17}'),
        'F064' : re.compile(r'[0-9A-Fa-f]{16}'),
    }
    
    def __init__(self, name, fmt, len_type, field_len = 0, compressed = True):
        self.name = name
        self.fmt = fmt
        self.len_type = len_type
        self.field_len = field_len
        self.compressed = compressed
        self.value = ''
        self.pack_value = ''
        self.error_info = ''
        
    def unpack(self, msg, multiplier = 0):
        if self.compressed:
            if self.len_type == self.LEN_FIXED:
                if self.fmt in (self.FMT_N, ):
                    lens = self.field_len
                else:
                    lens = self.field_len * 2
                
                if multiplier:
                    lens = (int(lens * multiplier) + 1) / 2 * 2
                
                self.value = msg[:lens]
                
                if self.fmt in (self.FMT_ANS,):
                    try:
                        self.value = self.value.decode('hex')
                    except:
                        pass
                
                r = self.pos_field_re.get(self.name)
                if r and not r.match(self.value):
                    self.error_info = 'ERR, field[%s] fmt invalid, [%s]' % (self.name, self.value)
                    return 
                    
                if self.fmt in (self.FMT_N, ):
                    return (lens + 1) / 2 * 2
                else:
                    return lens
            else:
                len_len = (self.len_type + 1) / 2 * 2
                try:
                    lens = int(msg[:len_len])
                except:
                    self.error_info = 'ERR, field[%s], parse len error, [%s]' % (self.name, msg[:len_len])
                    return
                
                if self.fmt in (self.FMT_ANS, self.FMT_BIT,):
                    lens = lens * 2
                elif self.fmt in (self.FMT_Z,):
                    lens = (lens + 1) / 2 * 2
                
                if multiplier:
                    lens = (int(lens * multiplier) + 1) / 2 * 2
                
                self.value = msg[len_len:len_len + lens]
                
                if self.fmt in (self.FMT_ANS,):
                    try:
                        self.value = self.value.decode('hex')
                    except:
                        pass
                
                r = self.pos_field_re.get(self.name)
                if r and not r.match(self.value):
                    self.error_info = 'ERR, field[%s] fmt invalid, [%s]' % (self.name, self.value)
                    return 
                
                if self.fmt in (self.FMT_N, ):
                    return len_len + (lens + 1) / 2 * 2
                else:
                    return len_len + lens
        else:
            if self.len_type == self.LEN_FIXED:
                lens = self.field_len * 2
                
                if multiplier:
                    lens = (int(lens * multiplier) + 1) / 2 * 2
                
                self.value = msg[:lens]
                if not self.fmt in (self.FMT_BIT, ):
                    try:
                        self.value = self.value.decode('hex')
                    except:
                        pass
                
                r = ins_field_re.get(self.name)
                if r and not r.match(self.value):
                    self.error_info = 'ERR, field[%s] fmt invalid, [%s]' % (self.name, self.value)
                    return 
                    
                return lens
            else:
                len_len = self.len_type * 2
                try:
                    lens = int(msg[:len_len].decode('hex')) * 2
                except:
                    self.error_info = 'ERR, field[%s], parse len error, [%s]' % (self.name, msg[:len_len])
                    return
                
                if multiplier:
                    lens = (int(lens * multiplier) + 1) / 2 * 2
                
                self.value = msg[len_len:len_len + lens]
                if not self.fmt in (self.FMT_BIT, ):
                    try:
                        self.value = self.value.decode('hex')
                    except:
                        pass
                
                r = ins_field_re.get(self.name)
                if r and not r.match(self.value):
                    self.error_info = 'ERR, field[%s] fmt invalid, [%s]' % (self.name, self.value)
                    return 
                
                return len_len + lens
    
    
    def pack(self):
        if self.compressed:
            value = self.value
            if self.pack_value:
                value = self.pack_value
            
            if not value:
                return ''
            
            if self.fmt in (self.FMT_ANS, ):
                if self.len_type == self.LEN_FIXED: 
                    s = value.ljust(self.field_len)[:self.field_len]
                    return s.encode('hex')
                else:
                    len_len = (self.len_type + 1) / 2 * 2
                    lens = ('%0' + '%d' % len_len + 'd') % len(value)
                    return lens + value.encode('hex')
                    
            elif self.fmt in (self.FMT_N,):
                if self.len_type == self.LEN_FIXED:
                    s = value.rjust(self.field_len, '0')[:self.field_len]
                    len_len = (self.field_len + 1) / 2 * 2
                    s = value.ljust(len_len, '0')[:len_len]
                    return s
                else:
                    len_len = (self.len_type + 1) / 2 * 2
                    lens = ('%0' + '%d' % len_len + 'd') % len(value)
                    return lens + value.ljust((len(value) + 1) / 2 * 2, '0')
            
            elif self.fmt in (self.FMT_BIT,):
                if self.len_type == self.LEN_FIXED:
                    s = value.ljust(self.field_len * 2)[:self.field_len * 2]
                    return s
                else:
                    len_len = (self.len_type + 1) / 2 * 2
                    lens = ('%0' + '%d' % len_len + 'd') % (len(value) / 2)
                    return lens + value
            
            elif self.fmt in (self.FMT_Z,):
                if self.len_type == self.LEN_FIXED: 
                    s = value.ljust(self.field_len)[:self.field_len]
                    return s
                else:
                    len_len = (self.len_type + 1) / 2 * 2
                    lens = ('%0' + '%d' % len_len + 'd') % len(value)
                    return lens + value.ljust((len(value) + 1) / 2 * 2, '0')
    
    
class Pos8583(object):
    
    pos_hide_field = set(['F002', 'F014', 'F035', 'F036', 'F062'])
    msg_type_re = re.compile(r'\A0[0-8][0-3]0\Z')
    
    def __init__(self, pik = '', mak = '', tdk = '', mac_mode = 'ECB'):
        self.pik = pik
        self.mak = mak
        self.tdk = tdk
        self.mac_mode = mac_mode
        
        self.fields = {
            #lli, lui, F006, F007, F009, F010, F051非标准格式
            'tpdu' :Field8583('tpdu', Field8583.FMT_N, Field8583.LEN_FIXED, 10),
            'lri' :Field8583('lri', Field8583.FMT_N, Field8583.LEN_FIXED, 132),
            'lli' :Field8583('lli', Field8583.FMT_N, Field8583.LEN_FIXED, 234),
            'lui' :Field8583('lui', Field8583.FMT_N, Field8583.LEN_FIXED, 160),
            'msg_head' :Field8583('msg_head', Field8583.FMT_N, Field8583.LEN_FIXED, 12),
            'msg_type' :Field8583('msg_type', Field8583.FMT_N, Field8583.LEN_FIXED, 4),
            'bitmap' :Field8583('bitmap', Field8583.FMT_BIT, Field8583.LEN_FIXED, 8),
            'F002' :Field8583('F002', Field8583.FMT_N, Field8583.LEN_VAR_2, 19),
            'F003' :Field8583('F003', Field8583.FMT_N, Field8583.LEN_FIXED, 6),
            'F004' :Field8583('F004', Field8583.FMT_N, Field8583.LEN_FIXED, 12),
            'F006' :Field8583('F006', Field8583.FMT_N, Field8583.LEN_FIXED, 12),
            'F007' :Field8583('F007', Field8583.FMT_N, Field8583.LEN_FIXED, 10),
            'F009' :Field8583('F009', Field8583.FMT_N, Field8583.LEN_FIXED, 8),
            'F010' :Field8583('F009', Field8583.FMT_N, Field8583.LEN_FIXED, 8),
            'F011' :Field8583('F011', Field8583.FMT_N, Field8583.LEN_FIXED, 6),
            'F012' :Field8583('F012', Field8583.FMT_N, Field8583.LEN_FIXED, 6),
            'F013' :Field8583('F013', Field8583.FMT_N, Field8583.LEN_FIXED, 4),
            'F014' :Field8583('F014', Field8583.FMT_N, Field8583.LEN_FIXED, 4),
            'F015' :Field8583('F015', Field8583.FMT_N, Field8583.LEN_FIXED, 4),
            'F022' :Field8583('F022', Field8583.FMT_N, Field8583.LEN_FIXED, 3),
            'F023' :Field8583('F023', Field8583.FMT_N, Field8583.LEN_FIXED, 3),
            'F024' :Field8583('F024', Field8583.FMT_N, Field8583.LEN_FIXED, 6),
            'F025' :Field8583('F025', Field8583.FMT_N, Field8583.LEN_FIXED, 2),
            'F026' :Field8583('F026', Field8583.FMT_N, Field8583.LEN_FIXED, 2),
            'F032' :Field8583('F032', Field8583.FMT_N, Field8583.LEN_VAR_2, 11),
            'F035' :Field8583('F035', Field8583.FMT_Z, Field8583.LEN_VAR_2, 37),
            'F036' :Field8583('F036', Field8583.FMT_Z, Field8583.LEN_VAR_3, 104),
            'F037' :Field8583('F037', Field8583.FMT_ANS, Field8583.LEN_FIXED, 12),
            'F038' :Field8583('F038', Field8583.FMT_ANS, Field8583.LEN_FIXED, 6),
            'F039' :Field8583('F039', Field8583.FMT_ANS, Field8583.LEN_FIXED, 2),
            'F040' :Field8583('F040', Field8583.FMT_ANS, Field8583.LEN_VAR_2, 512),
            'F041' :Field8583('F041', Field8583.FMT_ANS, Field8583.LEN_FIXED, 8),
            'F042' :Field8583('F042', Field8583.FMT_ANS, Field8583.LEN_FIXED, 15),
            'F044' :Field8583('F044', Field8583.FMT_ANS, Field8583.LEN_VAR_2, 25),
            'F048' :Field8583('F048', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 512),
            'F049' :Field8583('F049', Field8583.FMT_ANS, Field8583.LEN_FIXED, 3),
            'F051' :Field8583('F051', Field8583.FMT_ANS, Field8583.LEN_FIXED, 3),
            'F052' :Field8583('F052', Field8583.FMT_BIT, Field8583.LEN_FIXED, 8),
            'F053' :Field8583('F053', Field8583.FMT_N, Field8583.LEN_FIXED, 16),
            'F054' :Field8583('F054', Field8583.FMT_ANS, Field8583.LEN_VAR_3, 20),
            'F055' :Field8583('F055', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 255),
            'F057' :Field8583('F057', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 512),
            'F058' :Field8583('F058', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 100),
            'F060' :Field8583('F060', Field8583.FMT_N, Field8583.LEN_VAR_3, 17),
            'F061' :Field8583('F061', Field8583.FMT_N, Field8583.LEN_VAR_3, 29),
            'F062' :Field8583('F062', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 512),
            'F063' :Field8583('F063', Field8583.FMT_BIT, Field8583.LEN_VAR_3, 512),
            'F064' :Field8583('F064', Field8583.FMT_BIT, Field8583.LEN_FIXED, 8),
        }
    
    def unpack(self, msg, hide_flag = True):
        self.out_msg = []
        self.out_msg.append('报文解包...')
        
        msg = ''.join(msg.split())
        try:
            #检查是否存在报文长度域
            if abs(int(msg[:4], 16) - len(msg)/2) < 20:
                msg_len = int(msg[:4], 16)
                msg = msg[4 : 4 + msg_len * 2]
        except:
            pass
        
        msg_idx = 0
        for f in ['tpdu', 'lri', 'lli', 'lui', 'msg_head', 'msg_type', 'bitmap']:
            if f == 'lri' and msg[msg_idx:msg_idx+10].upper() != '4C5249001C':
                continue
            elif f == 'lli' and msg[msg_idx:msg_idx+10].upper() != '4C4C49001C':
                continue
            elif f == 'lui' and msg[msg_idx:msg_idx+10].upper() != '4C55490023':
                continue
            elif f == 'msg_head' and self.msg_type_re.match(msg[msg_idx:msg_idx+4]):
                #没有msg_head
                continue
                
            field = self.fields[f]
            parse_len = field.unpack(msg[msg_idx:])
            if parse_len:
                self.out_msg.append('field[%10s]:[%s]' % (field.name, field.value))
            else:
                self.out_msg.append(field.error_info)
                return (False, '\n'.join(self.out_msg))
            
            msg_idx += parse_len
                
        bitmap = hexstr_to_bitstr(self.fields['bitmap'].value)
                
        idx = 1
        while idx < 64:
            if idx < 1 or bitmap[idx] != '1':
                idx += 1
                continue
                
            key = 'F%03d' % (idx + 1)
            if key not in self.fields:
                self.out_msg.append('ERR, [%s] not support' % key)
                return (False, '\n'.join(self.out_msg))
            
            field = self.fields[key]
            
            if key in ('F048', 'F055', 'F057', 'F061', 'F062'):
                for m in (1, 0.5, 2):
                    parse_len = field.unpack(msg[msg_idx:], m)
                    #logger.debug(m, ',', field.value,',', msg[msg_idx + parse_len:]
                    if parse_len and self.try_unpack(msg, bitmap, idx + 1, msg_idx + parse_len):
                        break
            else:
                parse_len = field.unpack(msg[msg_idx:])
                
            if parse_len:
                if hide_flag and field.name in self.pos_hide_field:
                    if field.name == 'F062' and \
                        (field.value[:2] not in set(['01','02','03','04','05','06','07','90','92']) \
                        or field.value[:4] not in set(['3031','3032','3033','3034','3035','3036','3037','3930','3932'])):
                        self.out_msg.append('field[%10s]:[%s]' % (field.name, field.value))
                    else:
                        if field.name == 'F002':
                            self.out_msg.append('field[%10s]:[%s]' % (field.name, field.value[:6] + '*' * (len(field.value) - 10) + field.value[-4:]))
                        else:
                            self.out_msg.append('field[%10s]:[%s]' % (field.name, '*' * len(field.value)))
                else:
                    self.out_msg.append('field[%10s]:[%s]' % (field.name, field.value))
            else:
                self.out_msg.append(field.error_info)
                return (False, '\n'.join(self.out_msg))
            
            msg_idx += parse_len
            idx += 1
         
        return (True, '\n'.join(self.out_msg))
    
    
    def try_unpack(self, msg, bitmap, start_field, msg_idx):
        num = 0
        idx = start_field
        while idx < 64:
            if idx < 1 or bitmap[idx] != '1':
                idx += 1
                continue
                
            key = 'F%03d' % (idx + 1)
            if key not in self.fields:
                return False
            
            field = self.fields[key]
            if key in ('F048', 'F055', 'F057', 'F061', 'F062'):
                for m in (1, 0.5, 2):
                    parse_len = field.unpack(msg[msg_idx:], m)
                    if parse_len and self.try_unpack(msg, bitmap, idx + 1, msg_idx + parse_len):
                        break
            else:
                parse_len = field.unpack(msg[msg_idx:])
            
            if num >= 2:
                return True
            elif not parse_len:
                return False
            
            msg_idx += parse_len
            idx += 1
            num +=1
        
        return True
        
    
    def pack(self):
        logger.debug('报文组包...')
        msg = ''
        msg += self.fields['tpdu'].pack()
        msg += self.fields['lri'].pack()
        msg += self.fields['lli'].pack()
        msg += self.fields['lui'].pack()
        msg += self.fields['msg_head'].pack()        
        msg += self.fields['msg_type'].pack()
        mac_block = self.fields['msg_type'].pack()
        
        logger.debug('[%s]:[%s]' % ('tpdu', self.fields['tpdu'].value))
        if self.fields['lri'].value:
            logger.debug('[%s]:[%s]' % ('lri', self.fields['lri'].value))
        if self.fields['lli'].value:
            logger.debug('[%s]:[%s]' % ('lli', self.fields['lli'].value))
        if self.fields['lui'].value:
            logger.debug('[%s]:[%s]' % ('lui', self.fields['lui'].value))
        logger.debug('[%s]:[%s]' % ('msg_head', self.fields['msg_head'].value))
        logger.debug('[%s]:[%s]' % ('msg_type', self.fields['msg_type'].value))
        
        bitmap = ['0'] * 64
        
        self.get_pin()
        
        idx = 1
        while idx < 64:
            key = 'F%03d' % (idx + 1)
            if key in self.fields and self.fields[key].value:
                bitmap[idx] = '1'
            
            idx += 1
            continue
                
        self.fields['bitmap'].value = bitstr_to_hexstr(''.join(bitmap))
        
        msg += self.fields['bitmap'].pack()
        mac_block += self.fields['bitmap'].pack()
        logger.debug('[%s]:[%s]' % ('bitmap', self.fields['bitmap'].value))
                    
        idx = 1
        while idx < 63:
            key = 'F%03d' % (idx + 1)
            if key in self.fields and self.fields[key].value:
                logger.debug('[%s]:[%s]' % (key, self.fields[key].value))
                value = self.fields[key].pack()
                if len(value) % 2:
                    logger.error('[%s]:格式有误[%s]' % (key, self.fields[key].value))
                    return
                msg += value
                mac_block += value
            idx += 1
        
        if 'F064' in self.fields and self.fields['F064'].value:
            mac = self.get_mac(mac_block)
            if not mac:
                logger.error('mac计算失败')
                return
            logger.debug('[%s]:[%s]' % ('F064', mac))
            msg += mac
        logger.debug('send msg[%s]' % msg)
        msg = '%04X' % (len(msg)/2) + msg
        
        return msg.decode('hex')
    
    def get_mac(self, mac_block):
        if not self.mak:
            logger.error('无mak')
            return None
        if self.mac_mode == 'CBC':
            idx = len(self.mak)
            mac = des_encrypt(self.mak, mac_block, pyDes.CBC)[-idx:].upper()
        else:
            x = '0000000000000000'
            blocks = divide(mac_block, 16)
            for b in blocks:
                x = xor(x, b.ljust(16,'0'))
            mab = x.encode('hex')
            tmp = des_encrypt(self.mak, mab[:16]).upper()
            tmp = xor(tmp, mab[16:])
            mac = des_encrypt(self.mak, tmp).upper().encode('hex')[:16]
        return mac
    
    def get_pin(self):
        if not self.fields['F052'].value:
            self.fields['F026'].value = ''
            self.fields['F053'].value = ''
            return
        
        pin = self.fields['F052'].value
        self.fields['F026'].value = '%02d' % len(pin)
        pin = self.fields['F026'].value + pin + 'F' * (16 - len(pin) - 2)
        sec = self.fields['F053'].value
        if not sec:
            sec = '1600000000000000'
        if sec[0] == '2':
            card_no = self.fields['F002'].value
            if not card_no:
                track2 = self.fields['F035'].value
                card_no = ''
                for c in track2:
                    if c in ('d', 'D', '='):
                        break
                    card_no += c
                card_block = '0'*4 + card_no[-13:-1]
                pin = xor(pin, card_block)
        
        self.fields['F052'].value = des_encrypt(self.pik, pin).upper()
        if len(self.pik) == 16:
            self.fields['F053'].value = sec[0] + '0' + sec[2:]
        elif len(self.pik) == 32:
            self.fields['F053'].value = sec[0] + '6' + sec[2:]
        else:
            logger.error('pik length error[%s]' % self.pik)
        
        
class Pos(object):
    def __init__(self, trans_cfg_name, host = None):
        self.batch = '000001'
        self.ssn = '000001'
        self.msges = []
        
        self.host = pos_cfg.host
        self.bmk = pos_cfg.bmk
        self.mak = pos_cfg.mak
        self.pik = pos_cfg.pik
        self.tdk = pos_cfg.tdk
        self.mac_mode = pos_cfg.mac_mode
        
        self.term_id = pos_cfg.term_id
        self.mchnt_id = pos_cfg.mchnt_id
        
        self.card_no = pos_cfg.card_no
        self.pin = pos_cfg.pin
        self.track2 = pos_cfg.track2
        self.track3 = pos_cfg.track3
        
        self.trans_cfg_name = trans_cfg_name
        
        if host:
            self.host = host
        
    
    def init(self):
        self.get_pos_ssn()
        flag = self.get_trans_cfg()
        if not flag:
            logger.error('get trans cfg error')
            return
        self.connet(self.host)
        
        return True
        
        
    def connet(self, host):
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.skt.settimeout(30)
        self.skt.connect(host)
    
    
    def get_pos_ssn(self):
        if not os.path.exists(SSN_FILE):
            return
        cfg = {}
        fd = open(SSN_FILE, 'r+')
        lines = fd.readlines()
        for l in lines:
            l = l.strip()
            try:
                exec(l, cfg)
            except Exception, e:
                logger.debug(e)
                logger.debug(traceback.format_exc())
                
        fd.close()
        self.batch = cfg.get('batch', self.batch)
        self.ssn = cfg.get('ssn', self.ssn)
    
    
    def get_trans_cfg(self):
        module_name = os.path.basename(trans_cfg_name).replace('.py', '')
        module_name = 'trans.' + module_name
        try:
            __import__(module_name)
            self.trans_module = sys.modules[module_name]
        except Exception, e:
            logger.debug('加载交易配置文件[%s]失败' % self.trans_cfg_name)
            logger.debug(e)
            logger.debug(traceback.format_exc())
            return
        
        var = dir(self.trans_module)
        if 'host' in var:
            self.host = self.trans_module.host
        if 'bmk' in var:
            self.bmk = self.trans_module.bmk
        if 'mak' in var:
            self.mak = self.trans_module.mak
        if 'pik' in var:
            self.pik = self.trans_module.pik
        if 'tdk' in var:
            self.tdk = self.trans_module.tdk
        if 'mac_mode' in var:
            self.mac_mode = self.trans_module.mac_mode
            
        if 'term_id' in var:
            self.term_id = self.trans_module.term_id
        if 'mchnt_id' in var:
            self.mchnt_id = self.trans_module.mchnt_id
        
        if 'card_no' in var:
            self.card_no = self.trans_module.card_no
        if 'pin' in var:
            self.pin = self.trans_module.pin
        if 'track2' in var:
            self.track2 = self.trans_module.track2
        if 'track3' in var:
            self.track3 = self.trans_module.track3
        
        return True
        
    def update_pos_ssn(self):
        fd = open(SSN_FILE, 'w+')
        batch = int(self.batch)
        ssn = int(self.ssn)
        ssn += 1
        if ssn > 999999:
            batch += 1
            ssn = 1
        if batch > 999999:
            batch = 1
        self.batch = '%06d' % batch
        self.ssn = '%06d' % ssn
        
        fd.writelines(["batch = '%s'\n" % self.batch, "ssn = '%s'\n" % self.ssn])
    
    
    def update_key(self, resp):
        logger.debug('update_key')
        file_name = CONFIG_FILE
        fd = open(file_name, 'r+')
        lines = fd.readlines()
        fd.close()
        
        pik = ''
        mak = ''
        tdk = ''
        pik_ck = ''
        mak_ck = ''
        tdk_ck = ''
        
        f062 = resp.fields['F062'].value
        if len(f062) == 48:
            pik = f062[:16]
            pik_ck = f062[16:16+8]
            mak = f062[24:24+16]
            mak_ck = f062[40:40+8]
        elif len(f062) in (64, 80):
            pik = f062[:32]
            pik_ck = f062[32:32+8]
            mak = f062[40:40+16]
            if f062[56:-8] and f062[56:-8] != '0000000000000000':
                f062 += f062[56:-8]
            mak_ck = f062[-8:]
        elif len(f062) == 120:
            pik = f062[:32]
            pik_ck = f062[32:32+8]
            mak = f062[40:40+16]
            if f062[56:-48] and f062[56:-48] != '0000000000000000':
                mak += f062[56:-48]
            mak_ck = f062[72:72+8]
            tdk = f062[80:80+32]
            tdk_ck = f062[-8:]
        
        if pik:
            pik = des_decrypt(self.bmk, pik)
            if pik_ck !=  des_encrypt(pik, '0000000000000000')[:8]:
                logger.error('pik解密失败')
                return
            self.pik = pik
        if mak:
            mak = des_decrypt(self.bmk, mak)
            if mak_ck !=  des_encrypt(mak, '0000000000000000')[:8]:
                logger.error('mak解密失败')
                return
            self.mak = mak
        if tdk:
            tdk = des_decrypt(self.bmk, tdk)
            if tdk_ck !=  des_encrypt(tdk, '0000000000000000')[:8]:
                logger.error('mak解密失败')
                return
            self.tdk = tdk
            
        idx = 0
        while idx < len(lines):
            if lines[idx].startswith('mak'):
                lines[idx] = "mak = '%s'\n" % self.mak
            elif lines[idx].startswith('pik'):
                lines[idx] = "pik = '%s'\n" % self.pik
            elif lines[idx].startswith('tdk'):
                lines[idx] = "tdk = '%s'\n" % self.tdk
            idx += 1
            
        fd = open(file_name, 'w+')
        fd.writelines(lines)
        fd.close()
        return True
        
        
    def stop(self):
        self.skt.close()
    
    
    def resp_handler(self, resp):
        msg_type = resp.fields.get('msg_type').value
        f003 = ''
        f025 = ''
        f060 = ''
        if 'F003' in resp.fields:
            f003 = resp.fields.get('F003').value
        if 'F025' in resp.fields:
            f025 = resp.fields.get('F025').value
        if 'F060' in resp.fields:
            f060 = resp.fields.get('F060').value
        trans_type = msg_type + f003 + f025 + f060[:2] + f060[8:8 + 3]
        if trans_type in ('081000001', '081000003', '081000004'):
            #签到
            return self.update_key(resp)
        return True
        
        
    def send_trans(self, trans):
        module_dir = dir(self.trans_module)
        name = trans.get('name')
        if not name:
            logger.debug('trans no name', trans)
            return
        
        logger.debug('-' * 32)
        logger.debug('发送[%s]' % name)
        
        pos8583 = Pos8583(pik = self.pik, mak = self.mak, tdk = self.tdk, mac_mode = self.mac_mode)
        for k, v in trans.iteritems():
            if k in pos8583.fields:
                if type(v) == list:
                    idx = v[0]
                    func = v[1]
                    try:
                        m = self.msges[idx]
                    except Exception, e:
                        logger.error(e)
                        logger.error('[%s]配置非法，不存在的关联交易' % k)
                        return
                    if not self.msges[idx].req:
                        logger.debug('关联交易req失败')
                    
                    if not self.msges[idx].resp:
                        logger.debug('关联交易resp失败')
                    try:
                        pos8583.fields[k].value = func(self.msges[idx])
                    except Exception, e:
                        logger.error(e)
                        logger.error('[%s]取关联交易内容失败' % k)
                        return
                elif k == 'F002':
                    pos8583.fields[k].value = self.card_no
                elif k == 'F011':
                    pos8583.fields[k].value = self.ssn
                elif k == 'F035':
                    pos8583.fields[k].value = self.track2
                elif k == 'F036':
                    pos8583.fields[k].value = self.track3
                elif k == 'F041':
                    pos8583.fields[k].value = self.term_id
                elif k == 'F042':
                    pos8583.fields[k].value = self.mchnt_id
                elif k == 'F052':
                    pos8583.fields[k].value = self.pin
                elif k == 'F060':
                    pos8583.fields[k].value = v[:2] + self.batch + v[8:]
                else:
                    pos8583.fields[k].value = v
        
        msg = pos8583.pack()
        if not msg:
            logger.error('报文组包失败')
            return
        self.update_pos_ssn()
        
        self.skt.send(msg)
        self.msges.append(Msg(pos8583, None))
        
        recv_msg_len = 0
        while recv_msg_len == 0:
            try:
                recv_msg_len = self.skt.recv(2)
            except socket.timeout, e:
                logger.error(e)
                logger.error('接受报文超时')
                return
            except Exception, e:
                logger.error(e)
                logger.error('接受应答报文失败')
                return
            if recv_msg_len == '':
                logger.error('连接断开')
                return
            print 'recv_msg_len[%s]' % recv_msg_len.encode('hex')
            recv_msg_len = int(recv_msg_len.encode('hex'), 16)
        
        try:
            recv_msg = self.skt.recv(recv_msg_len)
        except socket.timeout, e:
            logger.error(e)
            logger.error('接受报文超时')
            return
        except Exception, e:
            logger.error(e)
            logger.error('接受应答报文失败')
            return
        recv_msg = recv_msg.encode('hex')
        logger.debug('recv msg[%s]' % recv_msg)
        
        pos8583 = Pos8583()
        flag, return_msg = pos8583.unpack(recv_msg, hide_flag = False)
        self.msges[-1] = Msg(self.msges[-1].req, pos8583)
        #for k, v in self.msges[-1].resp.fields.iteritems():
        #    logger.debug('[%s]:[%s]' % (k, v.value))
        logger.debug(return_msg)
        self.resp_handler(pos8583)
        return self.msges[-1]
        
    
    def send_all_trans(self):
        for trans in self.trans_module.all_trans:
            self.send_trans(trans)


def send_trans(trans_cfg_name, trans_name, host):
    
    pos = Pos(trans_cfg_name, host)
    flag = pos.init()
    if not flag:
        logger.error('pos init error')
        return
    
    if trans_name:
        trans = getattr(pos.trans_module, trans_name)
        pos.send_trans(trans)
    else:
        pos.send_all_trans()
    
    pos.stop()
    
    return

    
if __name__ == '__main__':
    host = None
    trans_name = ''
    argc = len(sys.argv)
    if argc == 2:
        trans_cfg_name = sys.argv[1]
    elif argc == 3:
        trans_cfg_name = sys.argv[1]
        trans_name = sys.argv[2]
    elif argc == 4:
        trans_cfg_name = sys.argv[1]
        host = (sys.argv[2], int(sys.argv[3]))
    elif argc == 5:
        trans_cfg_name = sys.argv[1]
        trans_name = sys.argv[2]
        host = (sys.argv[3], int(sys.argv[4]))
    else:
        logger.debug('usage: python %s trans_cfg_name [trans_name] [host_ip port]' % os.path.basename(__file__))
        sys.exit()
    
    send_trans(trans_cfg_name, trans_name, host)