# @Author: E-NoR
# @Date:   2022-12-19 16:05:21
# @Last Modified by:   E-NoR
# @Last Modified time: 2023-03-16 16:25:36
from functools import lru_cache
from platform import uname

from msgspec import DecodeError
from msgspec.json import decode as loads
from redis import ConnectionPool, Redis

try:
    from tomllib import TOMLDecodeError
    from tomllib import loads as tomlLoads
except ImportError:
    from tomli import TOMLDecodeError
    from tomli import loads as tomlLoads


def _parse(data, raw=False):
    """
    > 如果数据是有效的 JSON，则返回解析后的 JSON。
    > 如果数据是有效的 TOML，则返回解析的 TOML。
    > 如果数据既不是有效的 JSON 也不是有效的 TOML，则引发错误

    Args:
      data: 要解析的数据。

    Returns:
      Dict[str:Any]
    """
    if raw:
        return data
    try:
        return loads(data)
    except DecodeError:
        try:
            return tomlLoads(data)
        except TOMLDecodeError as e:
            raise TOMLDecodeError("解析失敗，請確認格式符合json或toml") from e


data = {"host": "192.168.32.26", "port": 6379, "db": 1, "password": "qatest666", "decode_responses": True}
# data = {"host": "192.168.32.27", "port": 6379, "db": 1, "password": "qatest666", "decode_responses": True}


def local_redis() -> ConnectionPool:
    return ConnectionPool(**data)


def redis_set(key, value, expired_sec=None):
    with Redis(**data) as r:
        return r.set(key, value, ex=expired_sec)


def redis_get(key, use_cache=True, raw=False):
    @lru_cache(maxsize=128)
    def _cache():
        with Redis(**data) as r:
            return r.get(key) if raw else _parse(r.get(key))

    def _no_cache():
        with Redis(**data) as r:
            return r.get(key) if raw else _parse(r.get(key))

    return _cache() if use_cache else _no_cache()


def redis_mget_all(key_list):  #
    with Redis(**data) as r:
        return [_parse(i) for i in r.mget(key_list)]


def redis_mset_all(key_list):  #
    with Redis(**data) as r:
        return r.mset(key_list)


def redis_load_any_db1(data_class: str):
    REDIS_POOL1 = ConnectionPool(**data)
    r = Redis(connection_pool=REDIS_POOL1)
    cached_response = r.hgetall(data_class)
    if cached_response is None:
        return None
    return cached_response


GAME_CONFIG, BACKEND_CONFIG, DEVICE_CONFIG = redis_mget_all(["game_setting", "backend_config", "device_config"])
# IS_DEV = uname().node in DEVICE_CONFIG["development"]["device_name"]
HTTP_HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
}
