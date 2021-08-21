'''
Part of the code comes from https://github.com/lclevy/firepwd/blob/master/firepwd.py
'''

import os 
import sys
import glob
import json
import sqlite3
import hmac
import time
from base64 import b64decode
from binascii import hexlify, unhexlify 
from pyasn1.codec.der import decoder
from struct import unpack
from hashlib import sha1, pbkdf2_hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from pathlib import Path
from Crypto.Util.Padding import unpad   


class firefox:
  USERPROFILE=os.environ['USERPROFILE']
  firefox_profile_path="/AppData/Roaming/Mozilla/Firefox/Profiles/*/"
  firefox_password_file='logins.json'

  def getShortLE(self, d, a):
    return unpack('<H',(d)[a:a+2])[0]

  def getLongBE(self, d, a):
    return unpack('>L',(d)[a:a+4])[0]

  #extract records from a BSD DB 1.85, hash mode  
  #obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used     
  def readBsddb(self, name):   
    f = open(name,'rb')
    #http://download.oracle.com/berkeley-db/db.1.85.tar.gz
    header = f.read(4*15)
    magic = self.getLongBE(header,0)
    if magic != 0x61561:
      #print ('bad magic number')
      sys.exit()
    version = self.getLongBE(header,4)
    pagesize = self.getLongBE(header,12)
    nkeys = self.getLongBE(header,0x38) 

    readkeys = 0
    page = 1
    nval = 0
    val = 1
    db1 = []
    while (readkeys < nkeys):
      f.seek(pagesize*page)
      offsets = f.read((nkeys+1)* 4 +2)
      offsetVals = []
      i=0
      nval = 0
      val = 1
      keys = 0
      while nval != val :
        keys +=1
        key = self.getShortLE(offsets,2+i)
        val = self.getShortLE(offsets,4+i)
        nval = self.getShortLE(offsets,8+i)
        #print 'key=0x%x, val=0x%x' % (key, val)
        offsetVals.append(key+ pagesize*page)
        offsetVals.append(val+ pagesize*page)  
        readkeys += 1
        i += 4
      offsetVals.append(pagesize*(page+1))
      valKey = sorted(offsetVals)  
      for i in range( keys*2 ):
        #print '%x %x' % (valKey[i], valKey[i+1])
        f.seek(valKey[i])
        data = f.read(valKey[i+1] - valKey[i])
        db1.append(data)
      page += 1
      #print 'offset=0x%x' % (page*pagesize)
    f.close()
    db = {}

    for i in range( 0, len(db1), 2):
      db[ db1[i+1] ] = db1[ i ]
    return db 

  def decryptMoz3DES(self, globalSalt, masterPassword, entrySalt, encryptedData ):
    #see http://www.drh-consultancy.demon.co.uk/key3.html
    hp = sha1( globalSalt+masterPassword ).digest()
    pes = entrySalt + b'\x00'*(20-len(entrySalt))
    chp = sha1( hp+entrySalt ).digest()
    k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
    k = k1+k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

  def decryptPBE(self, decodedItem, masterPassword, globalSalt):
    pbeAlgo = str(decodedItem[0][0][0])
    if pbeAlgo == '1.2.840.113549.1.12.5.1.3': #pbeWithSha1AndTripleDES-CBC
      """
      SEQUENCE {
        SEQUENCE {
          OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
          SEQUENCE {
            OCTETSTRING entry_salt
            INTEGER 01
          }
        }
        OCTETSTRING encrypted
      }
      """
      entrySalt = decodedItem[0][0][1][0].asOctets()
      cipherT = decodedItem[0][1].asOctets()
      #print('entrySalt:',hexlify(entrySalt))
      key = self.decryptMoz3DES( globalSalt, masterPassword, entrySalt, cipherT )
      #print(hexlify(key))
      return key[:24], pbeAlgo
    elif pbeAlgo == '1.2.840.113549.1.5.13': #pkcs5 pbes2  
      #https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6
      '''
      SEQUENCE {
        SEQUENCE {
          OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
          SEQUENCE {
            SEQUENCE {
              OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
              SEQUENCE {
                OCTETSTRING 32 bytes, entrySalt
                INTEGER 01
                INTEGER 20
                SEQUENCE {
                  OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
                }
              }
            }
            SEQUENCE {
              OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
              OCTETSTRING 14 bytes, iv 
            }
          }
        }
        OCTETSTRING encrypted
      }
      '''
      assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
      assert str(decodedItem[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
      assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
      # https://tools.ietf.org/html/rfc8018#page-23
      entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
      iterationCount = int(decodedItem[0][0][1][0][1][1])
      keyLength = int(decodedItem[0][0][1][0][1][2])
      assert keyLength == 32 

      k = sha1(globalSalt+masterPassword).digest()
      key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)    

      iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets() #https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
      # 04 is OCTETSTRING, 0x0e is length == 14
      cipherT = decodedItem[0][1].asOctets()
      clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)
      
      #print('clearText', hexlify(clearText))
      return clearText, pbeAlgo

  def decodeLoginData(self, data):
    '''
    SEQUENCE {
      OCTETSTRING b'f8000000000000000000000000000001'
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.3.7 des-ede3-cbc
        OCTETSTRING iv 8 bytes
      }
      OCTETSTRING encrypted
    }
    '''
    asn1data = decoder.decode(b64decode(data)) #first base64 decoding, then ASN1DERdecode
    key_id = asn1data[0][0].asOctets()
    iv = asn1data[0][1][1].asOctets()
    ciphertext = asn1data[0][2].asOctets()
    return key_id, iv, ciphertext 

  def getLoginData(self, logins_data_path):
    logins = []
    sqlite_file = logins_data_path/'signons.sqlite'
    json_file = logins_data_path/'logins.json'
    if json_file.exists(): #since Firefox 32, json is used instead of sqlite3
      loginf = open( json_file, 'r').read()
      jsonLogins = json.loads(loginf)
      if 'logins' not in jsonLogins:
        return [] # error: no \'logins\' key in logins.json
      for row in jsonLogins['logins']:
        encUsername = row['encryptedUsername']
        encPassword = row['encryptedPassword']
        logins.append( (self.decodeLoginData(encUsername), self.decodeLoginData(encPassword), row['hostname'], row['timeCreated']) )
      return logins  
    elif sqlite_file.exists(): #firefox < 32
      conn = sqlite3.connect(sqlite_file)
      c = conn.cursor()
      c.execute("SELECT * FROM moz_logins;")
      for row in c:
        encUsername = row[6]
        encPassword = row[7]
        logins.append( (self.decodeLoginData(encUsername), self.decodeLoginData(encPassword), row[1], row[10]) )
      return logins
    else: 
      return [] # missing logins.json or signons.sqlite

  CKA_ID = unhexlify('f8000000000000000000000000000001')

  def extractSecretKey(self, masterPassword, keyData): #3DES
    #see http://www.drh-consultancy.demon.co.uk/key3.html
    pwdCheck = keyData[b'password-check']
    entrySaltLen = pwdCheck[1]
    entrySalt = pwdCheck[3: 3+entrySaltLen]
    encryptedPasswd = pwdCheck[-16:]
    globalSalt = keyData[b'global-salt']
    cleartextData = self.decryptMoz3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
    if cleartextData != b'password-check\x02\x02':
      #print ('password check error, Master Password is certainly used, please provide it with -p option')
      sys.exit()

    if self.CKA_ID not in keyData:
      return None
    privKeyEntry = keyData[ self.CKA_ID ]
    saltLen = privKeyEntry[1]
    nameLen = privKeyEntry[2]
    #print 'saltLen=%d nameLen=%d' % (saltLen, nameLen)
    privKeyEntryASN1 = decoder.decode( privKeyEntry[3+saltLen+nameLen:] )
    data = privKeyEntry[3+saltLen+nameLen:]
    #see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
    '''
    SEQUENCE {
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
        SEQUENCE {
          OCTETSTRING entrySalt
          INTEGER 01
        }
      }
      OCTETSTRING privKeyData
    }
    '''
    entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
    privKeyData = privKeyEntryASN1[0][1].asOctets()
    privKey = self.decryptMoz3DES( globalSalt, masterPassword, entrySalt, privKeyData )
    #print ('decrypting privKeyData')
    '''
    SEQUENCE {
      INTEGER 00
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.1.1.1 pkcs-1
        NULL 0
      }
      OCTETSTRING prKey seq
    }
    ''' 
    privKeyASN1 = decoder.decode( privKey )
    prKey= privKeyASN1[0][2].asOctets()
    #print ('decoding %s' % hexlify(prKey))
    '''
    SEQUENCE {
      INTEGER 00
      INTEGER 00f8000000000000000000000000000001
      INTEGER 00
      INTEGER 3DES_private_key
      INTEGER 00
      INTEGER 00
      INTEGER 00
      INTEGER 00
      INTEGER 15
    }
    '''
    prKeyASN1 = decoder.decode( prKey )
    id = prKeyASN1[0][1]
    key = long_to_bytes( prKeyASN1[0][3] )
    return key

  def getKey(self, masterPassword, directory ):  
    if (directory / 'key4.db').exists():
      conn = sqlite3.connect(directory / 'key4.db') #firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
      c = conn.cursor()
      #first check password
      c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
      row = c.fetchone()
      globalSalt = row[0] #item1
      #print('globalSalt:',hexlify(globalSalt))
      item2 = row[1]
      #printASN1(item2, len(item2), 0)
      decodedItem2 = decoder.decode( item2 ) 
      clearText, algo = self.decryptPBE( decodedItem2, masterPassword, globalSalt )
    
      #print ('password check?', clearText==b'password-check\x02\x02')
      if clearText == b'password-check\x02\x02': 
        c.execute("SELECT a11,a102 FROM nssPrivate;")
        for row in c:
          if row[0] != None:
              break
        a11 = row[0] #CKA_VALUE
        a102 = row[1] 
        if a102 == self.CKA_ID: 
          decoded_a11 = decoder.decode( a11 )
          #decrypt master key
          clearText, algo = self.decryptPBE( decoded_a11, masterPassword, globalSalt )
          return clearText[:24], algo     
      return None, None
    elif (directory / 'key3.db').exists():
      keyData = self.readBsddb(directory / 'key3.db')
      key = self.extractSecretKey(masterPassword, keyData)
      return key, '1.2.840.113549.1.12.5.1.3'
    else:
      #print('cannot find key4.db or key3.db')  
      return None, None

  def run(self, target_list):
    result=[]
    if 'firefox' in target_list:
      logins_data_path=self.USERPROFILE+self.firefox_profile_path
      file_list=glob.glob(logins_data_path)
      if file_list:
        logins_data_path=Path(file_list[0])
        logins=self.getLoginData(logins_data_path)

        master_password=u''
        key, algo = self.getKey(  master_password.encode(), logins_data_path )
        #print(key)
        #print(algo)

        if len(logins)!=0:
          if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':  
            result_item={}
            desc="Firefox Passwords Data"
            result_item['desc']=desc
            data=[]
            for i in logins:
              assert i[0][0] == self.CKA_ID
              #print ('%20s:' % (i[2]))  #site URL
              data_item={}
              data_item['url']=i[2]
              #print (f"hostname: {i[2]}")  
              iv = i[0][1]
              ciphertext = i[0][2] 
              username=unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 )
              data_item['username']=str(username, encoding='utf-8')
              #print (f"username: {username}")
              iv = i[1][1]
              ciphertext = i[1][2] 
              password=unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 )
              data_item['password']=str(password,encoding='utf-8')
              #print (f"password: {password}")
              #creation_date=str(datetime.datetime(1601, 1, 1)+datetime.timedelta(milliseconds=i[3]))
              creation_date=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(i[3])/1000))
              data_item['creation_date']=creation_date
              #print(f"creation date: {creation_date}")
              data.append(data_item)
            result_item['data']=data
            result.append(result_item)
    return result