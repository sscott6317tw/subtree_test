# @Author: E-NoR
# @Date:   2023-01-19 12:39:39
# @Last Modified by:   E-NoR
# @Last Modified time: 2023-03-23 12:27:34
import asyncio
import math
import os
import time
from ast import literal_eval
from asyncio import Semaphore, create_task, gather
from contextlib import suppress
from copy import deepcopy
from datetime import date, datetime, timedelta
from hashlib import md5
from io import BytesIO
from re import findall
from urllib.parse import urlencode

import pygrab
from aiohttp import ClientPayloadError, ClientSession, ClientTimeout
from aiohttp_retry import ExponentialRetry, RetryClient
from loguru import logger
from msgspec.json import decode as loads
from msgspec.json import encode as dumps
from msgspec.json import format as js_format
from pandas import read_excel
from python_calamine.pandas import pandas_monkeypatch

from library.local_redis import BACKEND_CONFIG, HTTP_HEADER

DATE_FORMAT = "%Y-%m-%d"
DATE_TIME_FORMAT = "%Y-%m-%d %H:%M"
DATE_TIME_SECOND_FORMAT = "%Y-%m-%d %H:%M:%S"
pandas_monkeypatch()


class AioConnection:

    def __init__(self, platform) -> None:
        # with open(f"sw_{platform}.json", "rb") as f:
        #     self.parse_money = loads(f.read())
        self.is_session_tmp = False
        self.platform = platform
        self.cookies = None
        self.url = BACKEND_CONFIG[platform]["url"]
        self.pl_info = BACKEND_CONFIG[platform]
        self.session_sid = None

    def session(self) -> RetryClient:
        timeout = ClientTimeout(total=0)
        retry_options = ExponentialRetry(attempts=50)
        sid = self.session_sid
        self.headers = {
            "User-Agent": HTTP_HEADER["User-Agent"],
            "Cookie": f"connect.sid={sid}",
        }
        client_session = ClientSession(
            base_url=self.url,
            headers=self.headers,
            timeout=timeout,
        )
        return RetryClient(
            client_session=client_session,
            raise_for_status=False,
            retry_options=retry_options,
        )

    async def _login(self) -> tuple[str, str] | None:
        if "TT" in self.platform:
            return await self._login_tt()
        NAME = self.pl_info["acc"]
        if "_Proxy" not in self.platform and "_LAB" not in self.platform and "_HCI" in self.platform:
            if self.session_sid is not None:
                return self.session_sid
            while True:
                a = pygrab.get(f"http://192.168.32.26:8087/get_login_csid?platform={self.platform}", timeout=20).json()
                if '{"code":403' not in str(a):
                    break
                time.sleep(3)
            self.session_sid = a["data"]["connect.sid"]
            return self.session_sid

        LOGIN_URL, LOGIN_URL2 = "/default", "/login"
        if "HCI" in self.platform or "GKX" in self.platform:
            LOGIN_URL, LOGIN_URL2 = "/api/default", "/api/login"
        PASSWORD = md5(self.pl_info["pw"].encode("utf-8")).hexdigest()
        headers = HTTP_HEADER
        async with self.session() as session:
            async with session.get(LOGIN_URL) as resp:
                result = await resp.text()
                self.cookies = resp.cookies
            csrf_token = result[result.find('{"CSRF-Token": ') + 16 : result.find('{"CSRF-Token": ') + 52]
            if "<html>" in csrf_token:
                csrf_token = result[result.find("var csrf = '") + 12 : result.find("var csrf = '") + 48]
            payload = {
                "name": NAME,
                "password": PASSWORD,
                "validateCode": "",
                "count": "0",
                "isStrongPassword": "true",
                "isPwdOutdated": "true",
            }
            if "html" not in csrf_token:
                payload["_csrf"] = csrf_token
            else:
                with suppress(IndexError):
                    headers = HTTP_HEADER | literal_eval(findall("headers: ({ \"CSRF-Token\": '.*' })", result)[0])
            async with session.post(LOGIN_URL2, headers=headers, cookies=resp.cookies, data=payload) as rep:
                resp2 = await rep.text()
                if '{"code":0' not in resp2:
                    print(resp2)
                    raise ConnectionError(resp2)
                # a = "; ".join(f"{v.value}" for k, v in resp.cookies.items())
                a = resp.cookies["connect.sid"].value
                # "HCI_NW_DEV","HCI_YL","V8_HCI_DEV","V8_HCI_SIT","KX_HCI_DEV","V8_SIT_HCI","V8_HCI_TFSIT"
            if (
                self.platform
                in {"LY_MP", "LY_SIT", "KX_SIT", "LY_WC", "KX_WC", "KX_UAT", "KX_GLO_SIT", "KX_GKX", "KX_GLO_UAT"}
                or "HCI" in self.platform
            ):
                async with session.post(
                    "/2fa/status" if "HCI" not in self.platform and "GKX" not in self.platform else "/api/2fa/status",
                    headers=headers,
                    cookies=resp.cookies,
                ) as fa:
                    fa_msg = await fa.text()
                    if loads(fa_msg)["code"] == 1:
                        logger.info("AioConnection 執行 OTA 認證")
                        verify_url = "/api/2fa/verify"
                        code_resp = pygrab.get(
                            f"http://192.168.32.26:8087/get_2fa_code?platform={self.platform}&account={NAME}"
                        ).json()
                        if code_resp.get("code") == 0:
                            ota = code_resp.get("ota")
                            for code in ota:
                                async with session.post(verify_url, cookies=resp.cookies, json={"code": code}) as rep:
                                    fa_msg = await rep.text()
                                if loads(fa_msg).get("code") == 0:
                                    break
                        if '{"code":0' not in fa_msg or loads(fa_msg).get("code") != 0:
                            logger.error("AioConnection OTA 認證失敗,api server 取不到 code")
                            raise ConnectionError("AioConnection OTA 認證失敗,api server 取不到 code")
                    if '{"code":0' not in fa_msg:
                        print(fa_msg)
                        raise ConnectionError(fa_msg)
        self.session_sid = a
        return a

    async def _login_tt(self) -> tuple[str, str] | None:
        LOGIN_URL, LOGIN_URL2 = "/", "/api/users/login"
        NAME = self.pl_info["acc"]
        PASSWORD = self.pl_info["pw"]
        async with self.session() as session:
            payload = {
                "account": NAME,
                "password": PASSWORD,
            }
            async with session.post(LOGIN_URL2, data=payload) as rep:
                resp2 = await rep.text()
                if '"code":"OK"' not in resp2:
                    print(resp2)
                    raise ConnectionError(resp2)
                a = ";".join(f"{v.value}" for k, v in rep.cookies.items())
            async with session.get("/api/users/session", cookies=rep.cookies) as rep:
                resp2 = await rep.text()
                if '"code":"OK"' not in resp2:
                    print(resp2)
                    raise ConnectionError(resp2)
        self.tt_session_sid = a
        return a

    async def get_yl_range_data(self, agent_id, st, end, mode, dm=True):
        if self.session_sid is None:
            raise ValueError("no session_sid")

        from urllib.parse import urlencode

        if dm:
            date = self._get_date(st, end)
            base_data = lambda x: {
                "statisDate": x,
                "EndDate": x,
                "channelId": "0",
                "sort": mode,
                "limit": "20",
                "offset": "0",
                "total": "0",
                "proxyId": agent_id,
                "_": "",
            }
            url = "/DMStatisAgentInfo/initData?"
            date_data = [f"{url}{urlencode(base_data(i))}" for i in date]
        else:
            base_data = lambda: {
                "beginDate": st,
                "endDate": end,
                "sort": mode,
                "limit": "500000",
                "offset": "0",
                "total": "0",
                "proxyId": "",
                "_": "",
            }
            url = "/statisAgentInfo/initData?"
            date_data = [f"{url}{urlencode(base_data())}"]

            # if mode != "sort":
            #     mode ="sort"
            #     date_data.append()= [f"{url}{urlencode(base_data())}"]

        async with self.session() as session:
            tasks = [create_task(self.fetch(link, session)) for link in date_data]
            return await gather(*tasks)

    async def get_kx_ly_range_data(self, st, end, agent, mode):
        if self.session_sid is None:
            raise ValueError("no session_sid")
        date = self._get_date(st, end)
        # date = ['2023-03-03']
        base_data = lambda x: {
            "statisDate": x,
            "EndDate": x,
            "sort": mode,
            "limit": "500000",
            "offset": "0",
            "selOrder": "0",
            "total": "0",
            "channelId": "0",
            "agent": agent,
            "_": "",
        }
        from urllib.parse import urlencode

        url = "/statisAgentInfo/initData?"
        date_data = [f"{url}{urlencode(base_data(i))}" for i in date]

        async with self.session() as session:
            tasks = [create_task(self.fetch(link, session)) for link in date_data]
            s = await gather(*tasks)
            return s

    async def get_last_sum_profit(self, agent_id):
        if self.session_sid is None:
            raise ValueError("no session_sid")
        last_day = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")

        base_data = {
            "beginDate": last_day,
            "endDate": last_day,
            # "orderType": '',
            # "proxyName": '',
            # "createUser": '',
            "proxyName": agent_id,
            "limit": 1,
            "offset": 0,
            "total": 0,
            "orderstatus": "",
            "_": 1679542448021,
        }
        s = loads(await self.get("/proxyMoneyChangeDetail/initData?", params=base_data))
        return s["rows"][0]["NewScore"]

    async def get_singleWalletDetail(self, beginDate, endDate):
        api = "/api/singleWalletDetail/getData"
        base_data = lambda x, y: {
            "beginDate": x,
            "endDate": y,
            "orderId": "",
            "gameNo": "",
            "orderType": -1,
            "orderStatus": -1,
            "agent": "",
            "account": "",
            "pageSize": 100000,
            "page": 1,
        }
        date = self._get_date(beginDate, endDate, 30)

        date_data = [[date[date_loc], date[date_loc + 1]] for date_loc in range(len(date) - 1)]
        date_data = [f"{api}?{urlencode(base_data(i[0],i[1]))}" for i in date_data]
        print(f"開始抓取單一錢包上下分 : {str(len(date_data))} 筆")
        t = []
        async with self.session() as session:
            for link in date_data:
                async with session.get(link, timeout=ClientTimeout(60)) as response:
                    t.append(await response.text())

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])
        return data
        # date = self._get_date(beginDate, endDate,30)
        # api = "/api/singleWalletDetail/getData"

        # date_data = [[date[date_loc],date[date_loc+1]] for date_loc in range(len(date)-1)]
        # date_data = [f"{api}?{urlencode(base_data(i[0],i[1]))}" for i in date_data]

        # async with self.session() as session:
        #     tasks = [create_task(self.fetch(link, session)) for link in date_data]
        #     t = await gather(*tasks)

        # data = {}
        # data["rows"] = [d for i in t for d in loads(i)["rows"]]
        # data["total"] = len(data["rows"])
        # return data

    async def get_ly_all_detail_data(self, st, end, agent_id, mode):
        if self.session_sid is None:
            raise ValueError("no session_sid")

        url = "/proxyStatis/initData?"
        base_data = lambda x, agent, flag=False: {
            "beginDate": x,
            "endDate": x,
            "proxyName": agent if flag else "",
            "channelId": "" if flag else agent,
            "sort": "general",
            "limit": "10000",
            "offset": "0",
            "total": "0",
            "GameName": "全部",
            "_": "1678863664539",
        }

        async def get_agent_list(agent):
            agent_data = {}

            async def func(agent):
                nonlocal agent_data

                agent_url = [f"{url}{urlencode(base_data(i,agent))}" for i in date]
                async with self.session() as session:
                    tasks = [create_task(self.fetch(link, session)) for link in agent_url]
                    tmp_data = {m["ChannelID"]: m["ProxyCount"] for i in await gather(*tasks) for m in loads(i)["rows"]}
                for t, v in tmp_data.items():
                    if v > 0:
                        func(t)
                agent_data |= tmp_data

            await func(agent)
            return agent_data

        date = self._get_date(st, end)

        agent_list = {int(agent_id): 1}
        agent_list |= await get_agent_list(agent_id)

        date_data = [f"{url}{urlencode(base_data(i,agent_id,True))}" for i in date]
        date_data += [f"{url}{urlencode(base_data(i,ag))}" for i in date for ag, ct in agent_list.items() if ct > 0]

        async with self.session() as session:
            tasks = [create_task(self.fetch(link, session)) for link in date_data]
            t = await gather(*tasks)
            # m = [d for i in await gather(*tasks) for d in loads(i)['rows'] if d['ChannelID'] in agent_list]
        date += [t for t in date for _ in range(len(agent_list) - 1)]
        return date, [d for i in t for d in loads(i)["rows"]]

    async def fetch(self, link, session, default=50):
        while 1:
            with suppress(ClientPayloadError):
                async with Semaphore(default):
                    async with session.get(link, timeout=ClientTimeout(1200)) as response:  # 非同步發送請求
                        response_text = await response.text()
                        if '{"code":403' not in response_text:
                            break
                        await asyncio.sleep(3)
        return await response.text()

    async def get(self, link, params=None):
        if (not hasattr(self, "headers")) or (self.headers.get("Cookie") is None):
            self.headers = {
                "User-Agent": HTTP_HEADER["User-Agent"],
                "Cookie": f"connect.sid={self.session_sid}",
            }
        async with self.session() as session:
            async with session.get(link, headers=self.headers, params=params, timeout=ClientTimeout(120)) as response:  # 非同步發送請求
                if response.content_type.endswith("sheet"):
                    return read_excel(BytesIO(await response.read()))
                return await response.text()

    async def post(self, link, data=None):
        async with self.session() as session:
            async with session.post(link, headers=self.headers, data=data) as response:
                if response.status != 200:
                    raise ValueError(f"Request failed with status code {response.status}")
                return await response.text()

    async def get_agent_private_keys(self, agent):
        if "HCI" in self.platform or "GKX" in self.platform:
            url = (
                "/api/proxyaccount/getproxybyid" if "Proxy" not in self.platform else "/api/proxyaccountdl/getproxybyid"
            )
            data = {"id": agent}
        else:
            url = "/proxyaccount/getproxybyid"
            data = {"ChannelID": agent}
        M = await self.post(url, data=data)
        return M

    async def get_agent_list(self, mode, reduce_days=1):
        def _get_date_str() -> str:
            today = datetime.now() - timedelta(reduce_days)
            return today.date().strftime(DATE_FORMAT)

        date = _get_date_str()
        if self.platform in ["YL", "YL_WC"]:
            api = "/DMStatisAgentInfo/initData"
            ms = {
                "statisDate": date,
                "channelId": "0",
                "sort": mode,
                "limit": "500000",
                "offset": "0",
                "total": "0",
                "proxyId": "",
                "_": "1675995947909",
            }
        else:
            api = "/statisAgentInfo/initData"
            ms = {
                "statisDate": date,
                "EndDate": "",
                "sort": mode,
                "sortType": "5",
                "limit": "500000",
                "offset": 0,
                "total": 0,
                "agent": "",
                "_": "",
            }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_proxyMoney_ChangeDetail(self, beginDate="", endDate=""):
        api = "/api/proxyMoneyChangeDetail/list"
        ms = {
            "beginDate": f"{beginDate}",
            "endDate": f"{endDate}",
            "orderType": "",
            "agentId": "",
            "createUser": "",
            "orderStatus": "",
            "pageSize": 1,
            "page": 1,
        }

        from time import perf_counter

        link = f"{api}?{urlencode(ms)}"
        async with self.session() as session:
            t = await self.get(link)
            count = loads(t)["total"]
            req_link = []
            counts_flag = count / 100 + 1
            if counts_flag != 1:
                for i in range(counts_flag):
                    req_link.append(link.replace("pageSize=1", "pageSize=100").replace("page=1", f"page={str(i+1)}"))
            start = perf_counter()
            t = await gather(*(create_task(self.fetch(link, session, 20)) for link in req_link))
            end = perf_counter()
            print(end - start)

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])
        return data

    async def get_usermoney_changedetail(self, account, date=None, reduce_days=3):
        def _get_date_str() -> str:
            endDate = datetime.now()
            beginDate = endDate - timedelta(reduce_days)
            return endDate.date().strftime(DATE_FORMAT), beginDate.date().strftime(DATE_FORMAT)

        if date != None:
            beginDate = date.split("_")[0]
            endDate = date.split("_")[1]
        else:
            beginDate, endDate = _get_date_str()
        if "HCI" in self.platform:
            api = "/api/userMoneyChangeDetail/initData"
            ms = lambda account,pageSize,page: {
                "beginDate": f"{beginDate}",
                "endDate": f"{endDate}",
                "orderType": "",
                "accounts": account,
                "createUser": "",
                "orderStatus": "",
                "currency": "",
                "pageSize": pageSize,
                "page": page,
            }
        else:
            api = "/userMoneyChangeDetail/initData"
            ms = lambda account: {
                "beginDate": f"{beginDate}",
                "endDate": f"{endDate}",
                "createUser": "",
                "accounts": account,
                "orderStatus": "",
                "orderType": "",
                "total": "0",
                "limit": "10000000",
                "offset": "0",
            }
        if not isinstance(account, list):
            url = f"{api}?{urlencode(ms(account,10000,1))}"
            a = loads(await self.get(url))
            return loads(await self.get(url))
        else:
            from time import perf_counter, sleep

            t = []
            start = perf_counter()
            for acc in account:
                print(acc)
                url = f"{api}?{urlencode(ms(acc,1,1))}"
                rsp_data = loads(await self.get(url))  # 抓取總共有幾筆資料
                page_data = [
                    f"{api}?{urlencode(ms(acc,10000,page+1))}" for page in range(math.ceil(rsp_data["total"] / 10000))
                ]
                async with self.session() as session:
                    for link in page_data:
                        async with session.get(link, timeout=ClientTimeout(120)) as response:
                            t.append(await response.text())
            end = perf_counter()
            print(end - start)  #用下面的程式少了一半的時間
            # acc_data = [f"{api}?{urlencode(ms(acc))}" for acc in account ]
            # async with self.session() as session:
            #     t = await gather(*(create_task(self.fetch(link, session, 100)) for link in acc_data))
            #     count_list = [loads(i)["total"] for i in t]
            #     req_link = []
            #     for idx, data in enumerate(acc_data):
            #         counts_flag = count_list[idx] // 100 + 1
            #         if counts_flag != 1:
            #             for i in range(counts_flag):
            #                 req_link.append(data.replace("pageSize=1", "pageSize=100").replace("page=1", f"page={str(i+1)}"))
            #         elif count_list[idx] != 0 and counts_flag == 1:
            #             req_link.append(data.replace("pageSize=1", "pageSize=100"))
            #     from time import perf_counter

            #     start = perf_counter()
            #     print(f"開始抓取會員點數明細資料 : {str(len(req_link))} 支 API")
            #     t = await gather(*(create_task(self.fetch(link, session, 10)) for link in req_link))
            #     end = perf_counter()
            #     print(end - start)    

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
            data["total"] = len(data["rows"])
            return data

    async def get_linecode_list(self, agent_list):
        base_data = lambda x: {"channelId": x}
        from urllib.parse import urlencode

        url = "/proxyStatis/getAllLinecode?"
        date_data = [f"{url}{urlencode(base_data(i))}" for i in agent_list]

        async with self.session() as session:
            tasks = [create_task(self.fetch(link, session)) for link in date_data]
            return await gather(*tasks)

    async def get_exchangeRate_currencylist(self):
        if "Proxy" in self.platform:
            asyncio.run(AioConnection(self.platform.rsplit("_", 1)[0])._login())
        api = "/api/exchangeRate/getCurrencyList?"
        ms = {"currency": "", "pageSize": 50, "page": 1}
        url = f"{api}?{urlencode(ms)}"
        return loads(await self.get(url))

    async def get_OfflineList(self, account, beginDate, endDate):
        api = "/UserLogin/OfflineList"
        ms = lambda account: {
            "beginDate": beginDate,
            "endDate": endDate,
            "limit": "1000000",
            "offset": "0",
            "ip": "",
            "account": account,
            "total": "0",
        }
        url = f"{api}?{urlencode(ms(account))}"
        return loads(await self.get(url))

    async def special_get_winAndLoseReport_data(
        self, current_date=None, end_date=None, acc=None, gameid=None
    ):  # 遊戲留存監控特殊需求另外寫
        def _get_date_str(current_date, end_date) -> str:
            start_date = datetime.strptime(current_date, "%Y-%m-%d")  # 开始日期
            end_date = datetime.strptime(end_date, "%Y-%m-%d")
            current_date = start_date
            date_list = []
            while True:
                old_current_date = deepcopy(current_date)
                if current_date + timedelta(days=6) > end_date:
                    break
                # 七天要改為 6
                date_list.append(
                    (
                        current_date.date().strftime(DATE_FORMAT) + " 00:00",
                        (current_date + timedelta(days=6)).date().strftime(DATE_FORMAT) + " 23:59",
                    )
                )
                current_date += timedelta(days=6)
            date_list.append(
                (
                    old_current_date.date().strftime(DATE_FORMAT) + " 00:00",
                    end_date.date().strftime(DATE_FORMAT) + " 23:59",
                )
            )
            return date_list

        api = "/api/winAndLoseReport/getGameRecord"
        ms = lambda beginDate, endDate, gameid, acc: {
            "beginTime": beginDate,
            "endTime": endDate,
            "gameId": gameid,
            "roomId": "",
            "roomType": "",
            "currency": "",
            "gameNo": "",
            "account": acc,
            "pageSize": 1,
            "page": 1,
        }
        url = f"{api}?{urlencode(ms(1))}"
        rsp_data = loads(await self.get(url))  # 抓取總共有幾筆資料

        page_data = [f"{api}?{urlencode(ms(page+1))}" for page in range(math.ceil(rsp_data["total"] / 100))]
        t = []
        i = 0
        async with self.session() as session:
            for link in page_data:
                async with session.get(link, timeout=ClientTimeout(60)) as response:
                    t.append(await response.text())
                    i += 1
                    print(i)

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])

        return data

    async def get_winAndLoseReport_data(
        self, reduce_days=3, date=None, game_usr_no=None, account=None, limit=None, gameid=None
    ):  # 多加一個 limit 是為了，如果有太多資料，可以限制只抓幾筆
        def _get_date_str() -> str:
            endDate = datetime.now()
            beginDate = endDate - timedelta(reduce_days)
            return endDate.date().strftime(DATE_FORMAT), beginDate.date().strftime(DATE_FORMAT)

        if date != None:
            beginDate = date.split("_")[0]
            endDate = date.split("_")[1]
        else:
            if "KX" in self.platform and "HCI" not in self.platform and "GKX" not in self.platform:
                endDate = datetime.now() - timedelta(minutes=1)
                beginDate = endDate - timedelta(minutes=20)
                beginDate = beginDate.strftime(DATE_TIME_FORMAT)
                endDate = endDate.strftime(DATE_TIME_FORMAT)
            else:
                endDate, beginDate = _get_date_str()
                beginDate = (
                    f"{beginDate}+00:00"
                    if "HCI" not in self.platform and "GKX" not in self.platform
                    else f"{beginDate} 00:00"
                )
                endDate = (
                    f"{endDate}+23:59"
                    if "HCI" not in self.platform and "GKX" not in self.platform
                    else f"{endDate} 23:59"
                )
        if "KX" in self.platform and "HCI" not in self.platform and "GKX" not in self.platform:
            api = "/winAndLoseReport/InitData"
            if game_usr_no == None:
                base_data = lambda x, y: {
                    "beginDate": x,
                    "endDate": y,
                    "kindId": "",
                    "accounts": "",
                    "serverId": "",
                    "limit": 10000000,
                    "offset": 0,
                    "total": 0,
                    "GameUserNO": "",
                    "RoomType": "",
                }
            else:
                base_data = lambda x, y: {
                    "beginDate": x,
                    "endDate": y,
                    "kindId": "",
                    "accounts": "",
                    "serverId": "",
                    "limit": 10000000,
                    "offset": 0,
                    "total": 0,
                    "GameUserNO": game_usr_no,
                    "RoomType": "",
                }

            date = self._get_date(beginDate, endDate, 20)

            date_data = [[date[date_loc], date[date_loc + 1]] for date_loc in range(len(date) - 1)]
            date_data = [f"{api}?{urlencode(base_data(i[0],i[1]))}" for i in date_data]

            async with self.session() as session:
                tasks = [create_task(self.fetch(link, session)) for link in date_data]
                t = await gather(*tasks)

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            data["total"] = len(data["rows"])
            return data
        elif "YL_WC2" in self.platform:
            api = "/winAndLoseReport/InitData"
            ms = {
                "beginDate": beginDate,
                "endDate": endDate,
                "kindId": "",
                "accounts": "",
                "serverId": "",
                "limit": 10,
                "offset": 0,
                "total": 0,
                "GameUserNO": game_usr_no if game_usr_no != None else "",
                "RoomType": "",
            }
            url = f"{api}?{urlencode(ms)}"
            return loads(await self.get(url))
        else:
            api = (
                "/api/winAndLoseReport/getGameRecord"
                if "HCI" in self.platform or "GKX" in self.platform
                else "/winAndLoseReport/InitData"
            )
            if "HCI" not in self.platform and "GKX" not in self.platform:
                ms = {
                    "beginDate": beginDate,
                    "endDate": endDate,
                    "kindId": "",
                    "accounts": "",
                    "serverId": "",
                    "limit": 10000000,
                    "offset": 0,
                    "total": 0,
                    "GameUserNO": "",
                    "RoomType": "",
                }
                if game_usr_no != None:
                    ms["GameUserNO"] = game_usr_no
            else:
                if game_usr_no != None:
                    base_data = {
                        "beginTime": "",
                        "endTime": "",
                        "gameId": "",
                        "roomId": "",
                        "roomType": "",
                        "currency": "",
                        "gameNo": game_usr_no,
                        "account": "",
                        "pageSize": 1,
                        "page": 1,
                    }
                    url = f"{api}?{urlencode(base_data)}"
                    return loads(await self.get(url))
                elif isinstance(gameid,list):
                    base_data = lambda x, y, game: {
                        "beginTime": x,
                        "endTime": y,
                        "gameId": game,
                        "roomId": "",
                        "roomType": "",
                        "currency": "",
                        "gameNo": "",
                        "account": "" if account == None else account,
                        "pageSize": 1,
                        "page": 1,
                    }
                    filename = f"{self.platform}{account}{gameid[0]}_{beginDate.replace(':','_')}_{endDate.replace(':','_')}.json"
                    if not os.path.isfile(f"./compare_data/{filename}"):
                        req_link = []
                        for game in gameid:
                            if account == None:
                                date = self._get_date(beginDate, endDate, 10)
                            else:
                                date = self._get_date(beginDate, endDate, 8640)
                            date_data = [[date[date_loc], date[date_loc + 1]] for date_loc in range(len(date) - 1)]
                            date_data = [f"{api}?{urlencode(base_data(i[0],i[1],game))}" for i in date_data]
                            t = []
                            count_list = []
                            async with self.session() as session:
                                if "SIT" not in self.platform :
                                    total = 0
                                    for idx,link in enumerate(date_data):
                                        async with session.get(link, timeout=ClientTimeout(60)) as response:
                                            rsp_data = loads(await response.text())
                                            total += rsp_data["total"]
                                            count_list.append(total)
                                            get_info_count = idx + 1
                                            if total > limit:
                                                break
                                    date_data = date_data[:get_info_count]
                                else:
                                    t = await gather(*(create_task(self.fetch(link, session, 20)) for link in date_data))
                                    count_list = [loads(i)["total"] for i in t]
                                    if limit != None:
                                        total = 0
                                        for _idx, count in enumerate(count_list):
                                            total += count
                                            get_info_count = _idx + 1
                                            if total > limit:
                                                break
                                        if get_info_count == 1: #代表第一筆就大於我要抓的上限值，所以把第一筆改成我要抓的上限值
                                            count_list = [limit]
                                        else:
                                            count_list = count_list[:get_info_count]
                                        date_data = date_data[:get_info_count]
                                for idx, data in enumerate(date_data):
                                    counts_flag = count_list[idx] // 20 + 1
                                    if counts_flag != 1:
                                        for i in range(counts_flag):
                                            req_link.append(
                                                data.replace("pageSize=1", "pageSize=20").replace(
                                                    "page=1", f"page={str(i+1)}"
                                                )
                                            )
                                    elif count_list[idx] != 0 and counts_flag == 1:
                                        req_link.append(data.replace("pageSize=1", "pageSize=20"))
                                print(len(req_link))
                                # if len(req_link) == 0:
                                #     return {"rows": [], "total": 0}
                        async with self.session() as session:
                            t = await gather(*(create_task(self.fetch(link, session, 20)) for link in req_link))

                        data = {}
                        data["rows"] = [d for i in t for d in loads(i)["rows"]]
                        # 清除重複的
                        seen = set()
                        # 创建一个新的列表来存储去重后的字典
                        unique_data = []
                        # 遍历原始列表，仅将未出现过的gameNo对应的字典添加到新列表中
                        for d in data["rows"]:
                            game_no = d["gameNo"]
                            if game_no not in seen:
                                seen.add(game_no)
                                unique_data.append(d)
                        data["rows"] = unique_data
                        data["total"] = len(data["rows"])
                        with open(f"./compare_data/{filename}", "w", encoding="utf-8-sig") as file:
                            file.write(js_format(dumps(data), indent=2).decode("utf-8-sig"))
                    else:
                        with open(f"./compare_data/{filename}", encoding="utf-8-sig") as f:
                            data = loads(f.read())
                        # data["rows"] = [dict(t) for t in {tuple(d.items()) for d in data['rows']}] #清除重複的
                        # 清除重複的
                        seen = set()
                        # 创建一个新的列表来存储去重后的字典
                        unique_data = []
                        # 遍历原始列表，仅将未出现过的gameNo对应的字典添加到新列表中
                        for d in data["rows"]:
                            game_no = d["gameNo"]
                            if game_no not in seen:
                                seen.add(game_no)
                                unique_data.append(d)
                        data["rows"] = unique_data
                        data["total"] = len(data["rows"])
                    return data
                else:
                    base_data = lambda x, y: {
                        "beginTime": x,
                        "endTime": y,
                        "gameId": "" if gameid == None else gameid,
                        "roomId": "",
                        "roomType": "",
                        "currency": "",
                        "gameNo": "",
                        "account": "" if account == None else account,
                        "pageSize": 1,
                        "page": 1,
                    }
                    filename = f"{self.platform}{account}{gameid}_{beginDate.replace(':','_')}_{endDate.replace(':','_')}.json"
                    if not os.path.isfile(f"./compare_data/{filename}"):
                        if account == None:
                            date = self._get_date(beginDate, endDate, 10)
                        else:
                            date = self._get_date(beginDate, endDate, 8640)
                        date_data = [[date[date_loc], date[date_loc + 1]] for date_loc in range(len(date) - 1)]
                        date_data = [f"{api}?{urlencode(base_data(i[0],i[1]))}" for i in date_data]
                        t = []
                        async with self.session() as session:
                            t = await gather(*(create_task(self.fetch(link, session, 100)) for link in date_data))
                            count_list = [loads(i)["total"] for i in t]
                            if limit != None:
                                total = 0
                                for _idx, count in enumerate(count_list):
                                    total += count
                                    get_info_count = _idx + 1
                                    if total > limit:
                                        break
                                if get_info_count == 1: #代表第一筆就大於我要抓的上限值，所以把第一筆改成我要抓的上限值
                                    count_list = [limit]
                                else:
                                    count_list = count_list[:get_info_count]
                                date_data = date_data[:get_info_count]
                            req_link = []
                            for idx, data in enumerate(date_data):
                                counts_flag = count_list[idx] // 20 + 1
                                if counts_flag != 1:
                                    for i in range(counts_flag):
                                        req_link.append(
                                            data.replace("pageSize=1", "pageSize=20").replace(
                                                "page=1", f"page={str(i+1)}"
                                            )
                                        )
                                elif count_list[idx] != 0 and counts_flag == 1:
                                    req_link.append(data.replace("pageSize=1", "pageSize=20"))
                            print(len(req_link))
                            if len(req_link) == 0:
                                return {"rows": [], "total": 0}
                            t = await gather(*(create_task(self.fetch(link, session, 50)) for link in req_link))

                        data = {}
                        data["rows"] = [d for i in t for d in loads(i)["rows"]]
                        # 清除重複的
                        seen = set()
                        # 创建一个新的列表来存储去重后的字典
                        unique_data = []
                        # 遍历原始列表，仅将未出现过的gameNo对应的字典添加到新列表中
                        for d in data["rows"]:
                            game_no = d["gameNo"]
                            if game_no not in seen:
                                seen.add(game_no)
                                unique_data.append(d)
                        data["rows"] = unique_data
                        data["total"] = len(data["rows"])
                        if limit == None:  # 如果沒有設定抓取上限再存，不然存的資料會少
                            with open(f"./compare_data/{filename}", "w", encoding="utf-8-sig") as file:
                                file.write(js_format(dumps(data), indent=2).decode("utf-8-sig"))
                    else:
                        with open(f"./compare_data/{filename}", encoding="utf-8-sig") as f:
                            data = loads(f.read())
                        # data["rows"] = [dict(t) for t in {tuple(d.items()) for d in data['rows']}] #清除重複的
                        # 清除重複的
                        seen = set()
                        # 创建一个新的列表来存储去重后的字典
                        unique_data = []
                        # 遍历原始列表，仅将未出现过的gameNo对应的字典添加到新列表中
                        for d in data["rows"]:
                            game_no = d["gameNo"]
                            if game_no not in seen:
                                seen.add(game_no)
                                unique_data.append(d)
                        data["rows"] = unique_data
                        data["total"] = len(data["rows"])
                    return data
                # else:
                #     ms = lambda x: {
                #         "beginTime": beginDate,
                #         "endTime": endDate,
                #         "gameId": "",
                #         "roomId": "",
                #         "roomType": "",
                #         "currency": "",
                #         "gameNo": "",
                #         "account": "" if account == None else account,
                #         "pageSize": 1000,
                #         "page": x,
                #     }
                #     filename = f"{self.platform}{account}_{beginDate.replace(':','_')}_{endDate.replace(':','_')}.json"
                #     if not os.path.isfile(f"./compare_data/{filename}"):
                #         url = f"{api}?{urlencode(ms(1))}"
                #         rsp_data = loads(await self.get(url))  # 抓取總共有幾筆資料

                #         page_data = [f"{api}?{urlencode(ms(page+1))}" for page in range(math.ceil(rsp_data['total'] / 1000))]
                #         t = []
                #         i = 0
                #         async with self.session() as session:
                #             sem = 100
                #             t = await gather(*(create_task(self.fetch(link, session, sem)) for link in page_data))
                #             # for link in page_data:
                #             #     async with session.get(link, timeout=ClientTimeout(60)) as response:
                #             #         t.append(await response.text())
                #             #         i += 1
                #             #         print(i)

                #         data = {}
                #         data["rows"] = [d for i in t for d in loads(i)["rows"]]
                #         data["rows"] = [
                #             dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))
                #         ]  # 清除重複的
                #         data["total"] = len(data["rows"])
                #         with open(f"./compare_data/{filename}", "w", encoding="utf-8-sig") as file:
                #             file.write(js_format(dumps(data), indent=2).decode("utf-8-sig"))
                #     else:
                #         with open(f"./compare_data/{filename}", encoding="utf-8-sig") as f:
                #             data = loads(f.read())
                #     return data

            url = f"{api}?{urlencode(ms)}"
            return loads(await self.get(url))

    async def get_CashOrderDetail_data(self, begintime=None, endtime=None):

        def _get_date_str(begintime, endtime) -> str:
            if begintime == None:
                endtime = datetime.now()
                begintime = endtime - timedelta(1 if "HCI" in self.platform or "GKX" in self.platform else 6)
                return begintime.date().strftime(DATE_FORMAT), endtime.date().strftime(DATE_FORMAT)
            else:
                start_date = datetime.strptime(begintime, "%Y-%m-%d")  # 开始日期
                endtime = datetime.strptime(endtime, "%Y-%m-%d")
                begintime = start_date
                date_list = []
                if begintime == endtime:
                    date_list.append((begintime.date().strftime(DATE_FORMAT), endtime.date().strftime(DATE_FORMAT)))
                else:
                    while True:
                        old_begintime = deepcopy(begintime)
                        if begintime + timedelta(days=1) > endtime:
                            break
                        date_list.append(
                            (
                                begintime.date().strftime(DATE_FORMAT),
                                (begintime + timedelta(days=1)).date().strftime(DATE_FORMAT),
                            )
                        )
                        begintime += timedelta(days=1)
                    if begintime < endtime:
                        date_list.append(
                            (old_begintime.date().strftime(DATE_FORMAT), endtime.date().strftime(DATE_FORMAT))
                        )
                return date_list

        if begintime == None:
            beginDate, endDate = _get_date_str(begintime, endtime)
            data_list = [[beginDate, endDate]]
        else:
            data_list = _get_date_str(begintime, endtime)

        api = (
            "/api/cashOrderDetail/list"
            if "HCI" in self.platform or "GKX" in self.platform
            else "/CashOrderDetail/InitData"
        )
        if "HCI" in self.platform:
            ms = lambda x, y: {
                "beginDate": f"{x} 00:00",
                "endDate": f"{y} 23:59",
                "orderType": "",
                "currency": "",
                "accounts": "",
                "createUser": "",
                "pageSize": 10000,
                "page": "replace_page",
            }
            from time import perf_counter

            # start = perf_counter()
            # CashOrderDetail_data = [f"{api}?{urlencode(ms(i[0],i[1]))}" for i in data_list]
            # t = []
            # async with self.session() as session:
            #     for link in CashOrderDetail_data:
            #         get_total_link = link.replace("10000", "1")
            #         async with session.get(get_total_link, timeout=ClientTimeout(60)) as response:
            #             rsp_data = loads(await response.text())
            #         total_page = math.ceil(rsp_data["total"] / 10000)
            #         for page in range(total_page):
            #             async with session.get(
            #                 link.replace("replace_page", str(page + 1)), timeout=ClientTimeout(60)
            #             ) as response:
            #                 t.append(await response.text())
            # end = perf_counter()
            # print(end - start)
            ms = lambda x, y: {
                "beginDate": f"{x} 00:00",
                "endDate": f"{y} 23:59",
                "orderType": "",
                "currency": "",
                "accounts": "",
                "createUser": "",
                "pageSize": 1,
                "page": 1,
            }
            CashOrderDetail_data = [f"{api}?{urlencode(ms(i[0],i[1]))}" for i in data_list]
            t = []
            async with self.session() as session:
                t = await gather(*(create_task(self.fetch(link, session, 50)) for link in CashOrderDetail_data))
                count_list = [loads(i)["total"] for i in t ]
                req_link = []
                for idx,data in enumerate(CashOrderDetail_data):
                    counts_flag = count_list[idx] // 20 + 1
                    if counts_flag != 1:
                        for i in range(counts_flag):
                            req_link.append(data.replace("pageSize=1","pageSize=20").replace("page=1",f"page={str(i+1)}"))

                from time import perf_counter
                start = perf_counter()
                print(f"開始抓取現金網上下分 : {str(len(req_link))} 支 API")
                t = await gather(*(create_task(self.fetch(link, session, 10)) for link in req_link))
                end = perf_counter()
                print(end - start)

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
            data["total"] = len(data["rows"])
            return data
        else:
            ms = {
                "beginDate": f"{beginDate} 00:00",
                "endDate": f"{endDate} 23:59",
                "orderType": "" if "HCI" in self.platform or "GKX" in self.platform else "-2",
                "accounts": "",
                "createUser": "",
                "limit": 100000,
                "offset": 0,
                "total": 0,
            }
            url = f"{api}?{urlencode(ms)}"
            return loads(await self.get(url))

    async def get_gaminfo_data(self):
        api = "/api/gameInfo/getList"
        ms = {
            "pageSize": "1000",
            "page": "0",
            "status": "-1"
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_gamlog_data(self, gameNo):
        api = "/api/gameLog/log"
        ms = {"gameNo": gameNo}
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_gameresult_data(self, beginDate, endDate):
        api = "/api/GameResult/list"
        base_data = lambda x, y: {
            "beginDate": x,
            "endDate": y,
            "accounts": "",
            "gameNo": "",
            "kindId": "",
            "page": "1",
            "pageSize": "1",
            "serverId": "",
        }
        date = self._get_date(beginDate, endDate, 10)

        date_data = [[date[date_loc], date[date_loc + 1]] for date_loc in range(len(date) - 1)]
        date_data = [f"{api}?{urlencode(base_data(i[0],i[1]))}" for i in date_data]
        # print(f"開始抓取遊戲結果 : {str(len(date_data))} 筆")
        # t = []
        # async with self.session() as session:
        #     for idx,link in enumerate(date_data):
        #         print(idx)
        #         async with session.get(link, timeout=ClientTimeout(120)) as response:
        #             t.append(await response.text())

        # memberlink_list = [f"{api}?{urlencode(ms(i))}" for i in agent]
        t = []
        async with self.session() as session:
            t = await gather(*(create_task(self.fetch(link, session, 100)) for link in date_data))
            count_list = [loads(i)["total"] for i in t]
            req_link = []
            for idx, data in enumerate(date_data):
                counts_flag = count_list[idx] // 20 + 1
                if counts_flag != 1:
                    for i in range(counts_flag):
                        req_link.append(data.replace("pageSize=1", "pageSize=20").replace("page=1", f"page={str(i+1)}"))
                elif count_list[idx] != 0 and counts_flag == 1:
                    req_link.append(data.replace("pageSize=1", "pageSize=20"))
            from time import perf_counter

            start = perf_counter()
            print(f"開始抓取遊戲結果資料 : {str(len(req_link))} 支 API")
            t = await gather(*(create_task(self.fetch(link, session, 10)) for link in req_link))
            end = perf_counter()
            print(end - start)

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])
        return data

    async def get_orderStatusQuery_data(self, orderId_list):
        api = "/api/orderStatusQuery/getOrderStatus"
        base_data = lambda x: {"orderId": x}
        # url = f"{api}?{urlencode(ms)}"

        orderid_data = [f"{api}?{urlencode(base_data(i))}" for i in orderId_list]
        t = []
        async with self.session() as session:
            for idx, link in enumerate(orderid_data):
                print(idx)
                async with session.get(link, timeout=ClientTimeout(60)) as response:
                    t.append(await response.text())
        return t
        # all_data = []
        # batch_size = 1
        # async with self.session() as session:
        #     tasks = [create_task(self.fetch(link, session, 10)) for link in orderid_data]
        #     for i in range(0, len(tasks), batch_size):
        #         batch = tasks[i:i+batch_size]
        #         t = await gather(*batch)
        #         all_data += t
        # return all_data

        # return await gather(*tasks)

    async def get_proxy_info(self, agent, getchild=False):
        if "HCI" in self.platform or "GKX" in self.platform:
            api = "/api/proxyaccount/GetList" if "Proxy" not in self.platform else "/api/proxyaccountdl/getList"
            ms = {
                "account": "",
                "nickname": "",
                "id": "" if getchild == True or agent == None else f"{agent}",
                "proxyUId": f"{agent}" if getchild == True else "",
                "proxyUIds": f"{agent}" if getchild == True else "",
                "walletType": "",
                "minMoney": "",
                "maxMoney": "",
                "beginDate": "",
                "endDate": "",
                "currencyType": "-1",
                "page": 1,
                "pageSize": 1000000,
            }
        else:
            if "Proxy" in self.platform:
                api = "/proxyaccountdl/GetList"
            else:
                api = "/proxyaccount/GetList"
            if getchild == True:
                ms = {
                    "limit": "1000000",
                    "offset": "0",
                    "Accounts": "",
                    "proxyUID": f"{agent}",
                    "proxyUIDS": "",
                    "NickName": "",
                    "ChannelID": "",
                }
            else:
                ms = {
                    "limit": "1000000",
                    "offset": "0",
                    "Accounts": "",
                    "proxyUID": "",
                    "proxyUIDS": "",
                    "NickName": "",
                    "ChannelID": "" if agent == None else f"{agent}",
                }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_dailyProfitMonitor_info(self, date=None, acc=False):
        api = "/api/dailyProfitMonitor/getList"
        if date != None:
            beginDate = date.split("_")[0]
            endDate = date.split("_")[1]
        else:
            beginDate = endDate = ""

        ms = lambda acc: {  # HCI 用這個
            "startDate": beginDate,
            "endDate": endDate,
            "account": acc,
            "agent": "",
            "linecode": "",
            "pageSize": 1,
            "page": 1
        }
        acc = acc if isinstance(acc,list) else [acc]
        dailyprofit_list = [f"{api}?{urlencode(ms(i))}" for i in acc]
        t = []
        async with self.session() as session:
            t = await gather(*(create_task(self.fetch(link, session, 100)) for link in dailyprofit_list))
            count_list = [loads(i)["total"] for i in t]
            req_link = []
            for idx, data in enumerate(dailyprofit_list):
                counts_flag = count_list[idx] // 20 + 1
                if counts_flag != 1:
                    for i in range(counts_flag):
                        req_link.append(
                            data.replace("pageSize=1", "pageSize=20").replace("page=1", f"page={str(i+1)}")
                        )
                elif count_list[idx] != 0 and counts_flag == 1:
                    req_link.append(data.replace("pageSize=1", "pageSize=20"))
            from time import perf_counter

            start = perf_counter()
            print(f"開始抓取每日盈利監控資料 : {str(len(req_link))} 支 API")
            t = await gather(*(create_task(self.fetch(link, session, 30)) for link in req_link))
            end = perf_counter()
            print(end - start)

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["total"] = len(data["rows"])
        return data

    async def get_member_info(self, account=False, agent=False, date=None):
        if "HCI" in self.platform or "GKX" in self.platform:
            api = "/api/memberInfo/getList"
        else:
            api = "/memberInfo/GetList"

        if date != None:
            beginDate = date.split("_")[0]
            endDate = date.split("_")[1]
        else:
            beginDate = endDate = ""

        if isinstance(agent, list):
            ms = lambda agent: {  # HCI 用這個
                "account": "",
                "selStatus": -1,
                "agent": agent,
                "searchType": "1",
                "pageSize": 1,
                "page": 1,
                "beginDate": "" if date == None else beginDate,
                "endDate": "" if date == None else endDate,
            }

            memberlink_list = [f"{api}?{urlencode(ms(i))}" for i in agent]
            t = []
            async with self.session() as session:
                t = await gather(*(create_task(self.fetch(link, session, 100)) for link in memberlink_list))
                count_list = [loads(i)["total"] for i in t]
                req_link = []
                for idx, data in enumerate(memberlink_list):
                    counts_flag = count_list[idx] // 20 + 1
                    if counts_flag != 1:
                        for i in range(counts_flag):
                            req_link.append(
                                data.replace("pageSize=1", "pageSize=20").replace("page=1", f"page={str(i+1)}")
                            )
                    elif count_list[idx] != 0 and counts_flag == 1:
                        req_link.append(data.replace("pageSize=1", "pageSize=20"))
                from time import perf_counter

                start = perf_counter()
                print(f"開始抓取會員帳號資料 : {str(len(req_link))} 支 API")
                t = await gather(*(create_task(self.fetch(link, session, 30)) for link in req_link))
                end = perf_counter()
                print(end - start)

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            # 清除重複的
            seen = set()
            # 创建一个新的列表来存储去重后的字典
            unique_data = []
            # 遍历原始列表，仅将未出现过的gameNo对应的字典添加到新列表中
            for d in data["rows"]:
                acc = d["account"]
                if acc not in seen:
                    seen.add(acc)
                    unique_data.append(d)
            data["rows"] = unique_data
            data["total"] = len(data["rows"])
            return data
        elif account != "All" and isinstance(account, list) == False:
            if "HCI" in self.platform or "GKX" in self.platform:
                ms = {
                    "account": "" if account == False else account,
                    "pageSize": 50,
                    "selStatus": -1,
                    "searchType": 1,
                    "page": 1,
                    "agent": "" if agent == False else agent,
                    "endDate": endDate,
                    "beginDate": beginDate,
                }
            else:
                ms = {
                    "limit": "1",
                    "offset": "0",
                    "Accounts": "" if account == False else account,
                    "total": "0",
                    "selstatus": "-1",
                    "Proxyaccount": "" if agent == False else agent,
                    "hidserch": "1",
                    "BeginDate": "",
                    "EndDate": "",
                }
            url = f"{api}?{urlencode(ms)}"
            return await self.get(url)
        elif isinstance(account, list):
            ms = lambda account: {
                "account": account,
                "pageSize": 1,
                "selStatus": -1,
                "searchType": 1,
                "page": 1,
                "agent": "",
                "endDate": "",
                "beginDate": "",
            }
            memberlist_data = [f"{api}?{urlencode(ms(i))}" for i in account]

            # async with self.session() as session:
            #     tasks = [create_task(self.fetch(link, session, 10)) for link in memberlist_data]
            #     return await gather(*tasks)
            # rsp_data = []
            # for idx,acc in enumerate(account):
            #     url = f"{api}?{urlencode(ms(acc))}"
            #     rsp = loads(await self.get(url))
            #     print(idx)
            #     rsp_data += rsp["rows"]
            # return rsp_data
            t = []
            async with self.session() as session:
                for idx, link in enumerate(memberlist_data):
                    async with session.get(link, timeout=ClientTimeout(60)) as response:
                        t.append(await response.text())
                        print(idx)

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            data["total"] = len(data["rows"])
            return data
        elif account == "All":
            ms = lambda offset: {
                "limit": "10000",
                "offset": offset,
                "Accounts": "",
                "total": "0",
                "selstatus": "-1",
                "Proxyaccount": "",
                "hidserch": "1",
            }
            rsp_data = []
            offset = 0
            while offset < 990000 : #僅抓 1W 筆寫法
            # while True:
                try:
                    url = f"{api}?{urlencode(ms(offset))}"
                    rsp = loads(await self.get(url))
                    if len(rsp["rows"]) == 0:
                        break
                    else:
                        print(offset)
                        rsp_data += rsp["rows"]
                        offset += 10000
                except Exception as e:
                    offset += 10000
                    if "rows" in str(e):
                        1
                    print(str(e))
            return rsp_data

    async def get_proxyStatis_info(self, agent="", date="", sort="general"):
        def _get_date_str(current_date, end_date) -> str:
            start_date = datetime.strptime(current_date, "%Y-%m-%d")  # 开始日期
            end_date = datetime.strptime(end_date, "%Y-%m-%d")
            block_size = timedelta(days=30)
            date_list = []

            current_date = start_date
            while current_date <= end_date:
                block_end_date = min(current_date + block_size, end_date)
                date_list.append((current_date.strftime("%Y-%m-%d"), block_end_date.strftime("%Y-%m-%d")))
                current_date = block_end_date + timedelta(days=1)
            return date_list

        if "_" in date:
            beginDate = date.split("_")[0]
            endDate = date.split("_")[1]
        else:
            beginDate = endDate = date
        api = "/api/proxyStatis/initData"
        ms = lambda x, y, agent: {
            "beginDate": x,
            "endDate": y,
            "gameId": "",
            "typeAllId": "all",
            "agent": agent if agent != "" else agent,
            "uId": "",
            "currency": "",
            "searchType": "",
            "sort": sort,
            "pageSize": 1000000,
            "page": 1,
        }
        if not isinstance(agent, list):
            if (datetime.strptime(endDate, "%Y-%m-%d") - datetime.strptime(beginDate, "%Y-%m-%d")) > timedelta(days=60):
                data_list = _get_date_str(beginDate, endDate)
                userlogin_data = [f"{api}?{urlencode(ms(i[0],i[1],agent))}" for i in data_list]
                t = []
                async with self.session() as session:
                    for link in userlogin_data:
                        async with session.get(link, timeout=ClientTimeout(60)) as response:
                            t.append(await response.text())

                data = {}
                data["rows"] = [d for i in t for d in loads(i)["rows"]]
                data["total"] = len(data["rows"])
                return data
            else:
                url = f"{api}?{urlencode(ms(beginDate,endDate,agent))}"
                return loads(await self.get(url))
        else:
            date_data = [f"{api}?{urlencode(ms(beginDate,endDate,acc))}" for acc in agent]
            async with self.session() as session:
                tasks = [create_task(self.fetch(link, session)) for link in date_data]
                t = await gather(*tasks)

            data = {}
            data["rows"] = [d for i in t for d in loads(i)["rows"]]
            data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
            data["total"] = len(data["rows"])
            return data

    async def get_eventreceive_list(self, agent, reduce_days=1):
        def _get_date_str() -> str:
            endDate = datetime.now()
            beginDate = endDate - timedelta(reduce_days)
            return endDate.date().strftime(DATE_FORMAT), beginDate.date().strftime(DATE_FORMAT)

        endDate, beginDate = _get_date_str()
        api = "/api/eventLog/getEventReceiveList"
        ms = {
            "id": 5,  # 5 超級刮刮樂
            "player": "",
            "agentId": agent,
            "linecode": "",
            "startTime": beginDate,
            "endTime": endDate,
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_jackpot_list(self, agent, reduce_days=5):
        def _get_date_str() -> str:
            endDate = datetime.now()
            beginDate = endDate - timedelta(reduce_days)
            return endDate.date().strftime(DATE_FORMAT), beginDate.date().strftime(DATE_FORMAT)

        endDate, beginDate = _get_date_str()
        api = "/api/jackpotPayoutRecord/getList"
        ms = {
            "channelId": "" if agent == None else agent,  # jackpot
            "poolTier": "",
            "account": "",
            "pageSize": "",
            "page": "1",
            "beginDate": beginDate,
            "endDate": endDate,
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def get_userlogin_list(self, beginDate, endDate):
        api = "/UserLogin/InitData"

        def _get_date_str(current_date, end_date) -> str:
            start_date = datetime.strptime(current_date, "%Y-%m-%d")  # 开始日期
            end_date = datetime.strptime(end_date, "%Y-%m-%d")
            current_date = start_date
            date_list = []
            while True:
                old_current_date = deepcopy(current_date)
                if current_date + timedelta(days=1) > end_date:
                    break
                # 七天要改為 6
                date_list.append(
                    (
                        current_date.date().strftime(DATE_FORMAT),
                        (current_date + timedelta(days=0)).date().strftime(DATE_FORMAT),
                    )
                )
                current_date += timedelta(days=1)
            date_list.append((old_current_date.date().strftime(DATE_FORMAT), end_date.date().strftime(DATE_FORMAT)))
            return date_list

        ms = lambda x, y: {
            "beginDate": x,
            "endDate": y,
            "accounts": "",
            "loginIp": "",
            "ipblack": "",
            "limit": 100000,
            "offset": 0,
            "total": 0,
        }
        data_list = _get_date_str(beginDate, endDate)
        userlogin_data = [f"{api}?{urlencode(ms(i[0],i[1]))}" for i in data_list]
        t = []
        async with self.session() as session:
            for link in userlogin_data:
                while True:
                    async with session.get(link, timeout=ClientTimeout(60)) as response:
                        response_text = await response.text()
                    if '{"code":403' not in response_text:
                        break
                    time.sleep(3)
                t.append(response_text)
        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])
        return data

    async def get_gameRecordSort_data(self, beginDate, endDate):
        api = "/api/gameRecordSort/getList"

        def _get_date_str(current_date, end_date) -> str:
            start_date = datetime.strptime(current_date, "%Y-%m-%d")  # 开始日期
            end_date = datetime.strptime(end_date, "%Y-%m-%d")
            current_date = start_date
            date_list = []
            while True:
                old_current_date = deepcopy(current_date)
                if current_date + timedelta(days=3) > end_date:
                    break
                # 七天要改為 6
                date_list.append(
                    (
                        current_date.date().strftime(DATE_FORMAT),
                        (current_date + timedelta(days=3)).date().strftime(DATE_FORMAT),
                    )
                )
                current_date += timedelta(days=3)
            date_list.append((old_current_date.date().strftime(DATE_FORMAT), end_date.date().strftime(DATE_FORMAT)))
            return date_list

        ms = lambda x, y: {
            "beginDate": x,
            "endDate": y,
            "account": "",
            "gameId": "",
            "roomId": "",
            "agent": "",
            "currency": "",
            "lineCode": "",
            "sort": 2,
            "pageSize": 10000,
            "page": 1,
        }
        # if (datetime.strptime(endDate, "%Y-%m-%d") - datetime.strptime(beginDate, "%Y-%m-%d")).days + 1 > 7: #確認是否有超過七天，若超過七天，就需分割每七天抓一次數據
        data_list = _get_date_str(beginDate, endDate)
        gameRecordSort_data = [f"{api}?{urlencode(ms(i[0],i[1]))}" for i in data_list]
        t = []
        async with self.session() as session:
            for link in gameRecordSort_data:
                while True:
                    async with session.get(link, timeout=ClientTimeout(60)) as response:
                        response_text = await response.text()
                    if '{"code":403' not in response_text:
                        break
                    time.sleep(3)
                t.append(response_text)

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["rows"] = [dict(item) for item in (set(tuple(d.items()) for d in data["rows"]))]  # 清除重複的
        data["total"] = len(data["rows"])
        return data

    async def get_betDetial_data(self, beginDate, endDate):
        api = "/betDetial/InitData"

        def _get_date_str(current_date, end_date) -> str:
            start_date = datetime.strptime(current_date, "%Y-%m-%d")  # 开始日期
            end_date = datetime.strptime(end_date, "%Y-%m-%d")
            current_date = start_date
            date_list = []
            if current_date == end_date:
                date_list.append((beginDate, endDate))
            else:
                while True:
                    old_current_date = deepcopy(current_date)
                    if current_date + timedelta(days=2) > end_date:
                        break
                    date_list.append(
                        (
                            current_date.date().strftime(DATE_FORMAT),
                            (current_date + timedelta(days=2)).date().strftime(DATE_FORMAT),
                        )
                    )
                    current_date += timedelta(days=2)
                if current_date < end_date:
                    date_list.append(
                        (old_current_date.date().strftime(DATE_FORMAT), end_date.date().strftime(DATE_FORMAT))
                    )
            return date_list

        ms = lambda x, y: {
            "beginDate": f"{x} 00:00",
            "endDate": f"{y} 23:59",
            "accounts": "",
            "channelId": "",
            "limit": "100",
            "offset": "replace_page",
        }
        data_list = _get_date_str(beginDate, endDate)
        betDetial_data = [f"{api}?{urlencode(ms(i[0],i[1]))}" for i in data_list]
        # t = []
        # async with self.session() as session:
        #     for link in betDetial_data:
        #         async with session.get(link, timeout=ClientTimeout(120)) as response:
        #             t.append(await response.text())
        t = []
        import time

        async with self.session() as session:
            for link in betDetial_data:
                get_total_link = link.replace("100", "1").replace("replace_page", "0")
                async with session.get(get_total_link, timeout=ClientTimeout(60)) as response:
                    rsp_data = loads(await response.text())
                total_page = math.ceil(rsp_data["total"] / 100)
                for page in range(total_page):
                    async with session.get(
                        link.replace("replace_page", str(page)), timeout=ClientTimeout(120)
                    ) as response:
                        t.append(await response.text())
        end_time = time.time()

        data = {}
        data["rows"] = [d for i in t for d in loads(i)["rows"]]
        data["total"] = len(data["rows"])
        return data

    async def get_agentStatisticsData_data(self, beginDate, endDate):
        api = "/api/agentStatisticsData/getList"
        ms = {
            "beginDate": beginDate,
            "endDate": endDate,
            "agentId": "",
            "nickname": "",
            "currency": "",
            "sortType": "general",
            "pageSize": 10000,
            "page": 1,
        }
        async with self.session() as session:
            while True:
                async with session.get(f"{api}?{urlencode(ms)}", timeout=ClientTimeout(60)) as response:
                    response_text = await response.text()
                if '{"code":403' not in response_text:
                    break
                time.sleep(3)
            return  response_text
        # url = f"{api}?{urlencode(ms)}"
        # return await self.get(url)

    async def download_proxyStatis_excel(self, date):
        api = "/api/proxyStatis/exportData"
        ms = {
            "beginDate": date,
            "endDate": date,
            "gameId": "",
            "typeAllId": 0,
            "agent": "",
            "uId": "",
            "currency": "",
            "searchType": "",
            "sort": "general",
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_gameRecordSort_excel(self, date):
        #先確認導出列表是否有我要下載的日期
        api = "/api/gameRecordSort/getList"
        ms = {"listType": 1,}
        id = ""
        while True:
            gameRecordSort_data = await self.get(f"{api}?{urlencode(ms)}")
            if loads(gameRecordSort_data)["schedule"] == None:
                for i in range (len(loads(gameRecordSort_data)["rows"])):
                    beginDate,endDate = loads(loads(gameRecordSort_data)["rows"][i]["param"])["beginDate"],loads(loads(gameRecordSort_data)["rows"][i]["param"])["endDate"]
                    if date == beginDate and date == endDate :
                        id = loads(gameRecordSort_data)["rows"][i]["id"]
                        break
                if not id :
                    export_api = "/api/gameRecordSort/exportData"
                    gameRecordSort_ms = {
                            "beginDate": date,
                            "endDate": date,
                            "gameId": "",
                            "agent": "",
                            "lineCode": "",
                            "roomId": "",
                            "account": "",
                            "currency": "",
                            "sort": 2,
                        }
                    export_data = await self.get(f"{export_api}?{urlencode(gameRecordSort_ms)}")
                else:
                    break
            else:
                time.sleep(1)
        api = "/api/gameRecordSort/download"
        ms = {"id": id,}
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_roomBanishMonitor_excel(self, date):
        api = "/api/roomBanishMonitor/exportData"
        ms = {
            "beginDate": date,
            "endDate": date,
            "gameType": "",
            "roomType": "",
            "type": 0,
            "kdvalue": 0,
            "currency": "",
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_roomMonitoring_excel(self, date):
        api = "/api/roomMonitoring/ExportData"
        ms = {
            "beginDate": date,
            "endDate": date,
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_agentStatisticsData_excel(self, date):
        api = "/api/agentStatisticsData/export"
        ms = {
            "beginDate": date,
            "endDate": date,
            "agentId": "",
            "nickname": "",
            "currency": "",
            "sortType": "general",
        }
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_agentStatisticsData_MonthDataexcel(self, date):
        api = "/api/agentStatisticsData/exportMonthData"
        ms = {"date": date}
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def download_deliveryreport_excel(self, date):
        api = "/api/deliveryreport/exportData"
        ms = {"statisDate": date, "channelId": "", "pageSize": "", "page": ""}
        url = f"{api}?{urlencode(ms)}"
        return await self.get(url)

    async def s6_api(self, record_url, agent, timestamp, paramData, key):
        if "NW" in self.platform:
            payload = {
                "channel": agent,
                "mTime": timestamp,
                "paramerter": paramData,
                "key": key,
            }
        else:
            payload = {
                "agent": agent,
                "timestamp": timestamp,
                "param": paramData,
                "key": key,
            }
        url = f"{record_url}?{urlencode(payload)}"
        return await self.get(url)

    @staticmethod
    def _get_date(start=None, end=None, min=False):
        if min and ":" not in start:
            start += " 00:00:00"
            end += " 00:00:00"
        # elif "23:59" in end :
        #     end = str(datetime.strptime(end, DATE_TIME_FORMAT if min else DATE_FORMAT)+timedelta(minutes=1))
        if str(start).count(":") == 1:
            datestart = datetime.strptime(start, DATE_TIME_FORMAT if min else DATE_FORMAT)
            dateend = datetime.strptime(end, DATE_TIME_FORMAT if min else DATE_FORMAT)
        else:
            datestart = datetime.strptime(start, DATE_TIME_SECOND_FORMAT if min else DATE_FORMAT)
            dateend = datetime.strptime(end, DATE_TIME_SECOND_FORMAT if min else DATE_FORMAT)

        data_list = []
        while datestart <= dateend:
            if str(start).count(":") == 1:
                data_list.append(datestart.strftime(DATE_TIME_FORMAT if min else DATE_FORMAT))
            else:
                data_list.append(datestart.strftime(DATE_TIME_SECOND_FORMAT if min else DATE_FORMAT))
            if min:
                datestart += timedelta(minutes=min)  # 帶入要分割的時間
            else:
                datestart += timedelta(days=1)
            if datestart > dateend:
                data_list.append(dateend.strftime("%Y-%m-%d %H:%M"))  # 把最後一筆 append 進去
        return data_list


if __name__ == "__main__":
    m = asyncio.run(AioConnection("YL")._login())
    print(m)
