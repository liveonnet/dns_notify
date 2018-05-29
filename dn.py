#-#import pathlib
import json
import yaml
import asyncio
import aiohttp
from aiohttp.resolver import AsyncResolver
from hashlib import sha1
from hashlib import sha256
from base64 import b64encode
#-#from base64 import b64decode
#-#from Crypto import HMAC, SHA256
import hmac
from urllib import parse
from time import time
from random import randint
from applib.tools_lib import pcformat
from applib.conf_lib import getConf
from applib.log_lib import app_log
info, debug, error, warn = app_log.info, app_log.debug, app_log.error, app_log.warning


class QcloudManager(object):
    def __init__(self, loop=None):
        self.loop = loop
        self.conf = getConf('config/dn.yaml')

        resolver = AsyncResolver(nameservers=['8.8.8.8', '8.8.4.4'])
        conn = aiohttp.TCPConnector(resolver=resolver, limit=10)
        if self.loop:
            self.sess = aiohttp.ClientSession(connector=conn, headers={'User-Agent': self.conf['user_agent']}, loop=self.loop)
        else:
            self.sess = aiohttp.ClientSession(connector=conn, headers={'User-Agent': self.conf['user_agent']})

    async def clean(self):
        await self.sess.close()
        info('sess closed')

    def getSign(self, method, url, d):
#-#        sign_method = self.hmac_sha1 if d.get('SignatureMethod', 'HmacSHA1') == 'HmacSHA1' else self.hmac_sha256
        pr = parse.urlparse(url)
        domain, path = pr.netloc, pr.path
        s = b'&'.join(b'%s=%s' % (_k.replace('_', '.').encode('utf8'), _v.encode('utf8') if isinstance(_v, str) else _v) for _k, _v in sorted((_k, _v if isinstance(_v, (str, bytes)) else str(_v)) for _k, _v in d.items() if _k != 'Signature'))
#-#        info('s=%s', s)
        sign_raw = b'%s%s%s?%s' % (method.upper().encode('utf8'), domain.encode('utf8'), path.encode('utf8'), s)
#-#        info('sign_raw=%s', sign_raw)
        sign = b64encode(hmac.new(self.conf['SecretKey'].encode('utf8'), msg=sign_raw, digestmod=sha1 if d.get('SignatureMethod', 'HmacSHA1') == 'HmacSHA1' else sha256).digest())
        return sign

    def Sign(self, method, url, d):
        d['Signature'] = self.getSign('GET', url, d).decode('utf8')
        return d

    def getPubArg(self, action):
        d = {'Action': action,
             'Region': 'bj',
             'Timestamp': int(time()),
             'Nonce': randint(100000000, 400000000),
             'SecretId': self.conf['SecretId'],
             'Signature': None,
             'SignatureMethod': 'HmacSHA1',
             }
        return d

    async def _getData(self, url, *args, **kwargs):
        """封装网络请求

        my_fmt:
            str:
                my_str_encoding
            json:
                my_json_encoding
                my_json_loads
            bytes:
                None
            streaming:
                my_streaming_chunk_size
                my_streaming_cb
        """
        resp, data, ok = None, None, False
        str_encoding = kwargs.pop('my_str_encoding', None)
        fmt = kwargs.pop('my_fmt', 'str')
        json_encoding = kwargs.pop('my_json_encoding', None)
        json_loads = kwargs.pop('my_json_loads', json.loads)
        streaming_chunk_size = kwargs.pop('my_streaming_chunk_size', 1024)
        streaming_cb = kwargs.pop('my_streaming_cb', None)
        max_try = kwargs.pop('my_retry', 1)

        for nr_try in range(max_try):
            try:
#-#                debug('url %s %s %s', url, pcformat(args), pcformat(kwargs))
                resp = await self.sess.get(url, *args, **kwargs)
                if fmt == 'str':
                    try:
                        data = await resp.text(encoding=str_encoding)
                    except UnicodeDecodeError:
                        txt = await resp.read()
                        data = txt.decode(str_encoding, 'ignore')
#-#                        warn('ignore decode error from %s', url)
                elif fmt == 'json':
                    try:
                        data = await resp.json(encoding=json_encoding, loads=json_loads)
                    except aiohttp.client_exceptions.ContentTypeError:
#-#                        warn('ContentTypeError, try decode json ...')
                        try:
                            data = await resp.text(encoding=json_encoding)
                        except UnicodeDecodeError:
                            txt = await resp.read()
                            data = txt.decode(str_encoding, 'ignore')
                        try:
                            data = json.loads(data)
                        except:
                            error('json except', exc_info=True)

#-#                    if not data:
#-#                    if 'json' not in resp.headers.get('content-type', ''):
#-#                        warn('data not in json? %s', resp.headers.get('content-type', ''))
                elif fmt == 'bytes':
                    data = await resp.read()
                elif fmt == 'stream':
                    while 1:
                        chunk = await resp.content.read(streaming_chunk_size)
                        if not chunk:
                            break
                        streaming_cb(url, chunk)
                ok = True
                break
            except aiohttp.ServerDisconnectedError:
                info('%sServerDisconnectedError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs))
            except asyncio.TimeoutError:
                info('%sTimeoutError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs))
            except aiohttp.ClientConnectionError:
                error('%sConnectionError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs))
#-#            except aiohttp.errors.ClientHttpProcessingError:
#-#                error('%sClientHttpProcessingError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs), exc_info=True)
            except aiohttp.client_exceptions.ContentTypeError:
                error('%sContentTypeError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs), exc_info=True)
#-#            except aiohttp.ClientTimeoutError:
#-#                error('%sClientTimeoutError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs))
            except aiohttp.ClientError:
                error('%sClientError %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs), exc_info=True)
            except UnicodeDecodeError:
#-#                txt = await resp.read()
#-#                open('/tmp/txt_%s.html' % time.time(), 'wb').write(txt)
                error('%sUnicodeDecodeError %s %s %s %s\n%s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs), pcformat(resp.headers), txt[:100], exc_info=True)
                break
#-#                raise e
            except Exception:
                error('%sException %s %s %s', ('%s/%s ' % (nr_try + 1, max_try)) if max_try > 1 else '', url, pcformat(args), pcformat(kwargs), exc_info=True)
            finally:
                if resp:
                    resp.release()

        return resp, data, ok

    async def getRecordList(self, sub_domain='', record_type='A'):
        rtn = []
        url = self.conf['url']
        d = {'domain': self.conf['Domain'],
             }
        if sub_domain:
             d['subDomain'] = sub_domain
        if record_type:
             d['recordType'] = record_type
        d.update(self.getPubArg('RecordList'))
        self.Sign('GET', url, d)
        _, j_data, ok = await self._getData(url, params=d, timeout=10, my_fmt='json', my_json_encoding='utf8')
        if ok and j_data['code'] == 0:
#-#            debug('resp %s', pcformat(j_data))
            rtn = j_data.get('data', {}).get('records', [])
        else:
            info('error ? %s %s', ok, pcformat(j_data))
        return rtn


    async def changeRecord(self, recodrd_id, val, sub_domain='', record_type='A', record_line='默认'):
        rtn = {}
        url = self.conf['url']
        d = {'domain': self.conf['Domain'],
             'recordId': recodrd_id,
             'recordLine': record_line,
             'value': val,
             }
        if sub_domain:
             d['subDomain'] = sub_domain
        if record_type:
             d['recordType'] = record_type
        d.update(self.getPubArg('RecordModify'))
        self.Sign('GET', url, d)
        _, j_data, ok = await self._getData(url, params=d, timeout=10, my_fmt='json', my_json_encoding='utf8')
        if ok and j_data['code'] == 0:
#-#            debug('resp %s', pcformat(j_data))
            rtn = j_data.get('data', {}).get('record', {})
        else:
            info('error ? %s %s', ok, pcformat(j_data))
        return rtn


    async def changeDomainIp(self, ip, sub_domain=''):
        assert ip
        r = await self.getRecordList(sub_domain)
        if r:
            r = r[0]
            name, updated_on, record_id, old_ip = r['name'], r['updated_on'], r['id'], r['value']
#-#            info('%s(id %s) ip %s @%s', name, record_id, old_ip, updated_on)
            if old_ip != ip:
                rtn = await self.changeRecord(record_id, ip, sub_domain)
                info('%s(id %s) ip %s -> %s res:\n%s', name, record_id, old_ip, ip, pcformat(rtn))
            else:
                info('%s(id %s) ip not change %s', name, record_id, old_ip)
        else:
            info('no record matching sub domain %s', sub_domain)

    async def changeIp(self):
        _, j_data, ok = await self._getData('http://httpbin.org/ip', timeout=5, my_fmt='json')
        if ok and j_data:
            ip = j_data.get('origin')
            info('got my ip %s', ip)
            await self.changeDomainIp(ip, '@')
            await self.changeDomainIp(ip, 'wx')
            await self.changeDomainIp(ip, 'blog')
            await self.changeDomainIp(ip, 'www')


if __name__ == '__main__':
    async def test_main(loop):
        qm = QcloudManager(loop)
        await qm.changeIp()
        await qm.clean()

    loop = asyncio.get_event_loop()
    try:
        task = asyncio.ensure_future(test_main(loop))
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        info('cancel on KeyboardInterrupt..')
        task.cancel()
        loop.run_forever()
        task.exception()
    finally:
        loop.stop()



