#!/usr/bin/env python3
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import html
import aiomysql
import bcrypt
import os.path
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.locks
import tornado.options
import tornado.web
from urllib.parse import unquote
from datetime import datetime

from tornado.options import define, options
from ui_module import ui_modules

define("port", default=8888, help="run on the given port", type=int)
define("db_host", default="127.0.0.1", help="blog database host")
define("db_port", default=3306, help="blog database port")
define("db_database", default="blog", help="blog database name")
define("db_user", default="root", help="blog database user")
define("db_password", default="123456", help="blog database password")


class NoResultError(Exception):
    pass


class AttrDict(dict):
    """Dict that can get attribute by dot, and doesn't raise KeyError"""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None


class AttrDictCursor(aiomysql.DictCursor):
    dict_type = AttrDict


class Application(tornado.web.Application):
    def __init__(self, db):
        self.db = db
        handlers = [
            (r"/", HomeHandler),
            (r"/feed", FeedHandler),
            (r"/auth/create/?", AuthCreateHandler),
            (r"/auth/login/?", AuthLoginHandler),
            (r"/auth/logout/?", AuthLogoutHandler),
            (r"/article/create/?", CreateHandler),
            (r"/article/save/?", ArticleSaveHandler),
            (r"/article/detail/([^/]+)/?", ArticleDetailHandler),
            (r"/article/edit/?", ArticleEditHandler),
        ]
        settings = dict(
            blog_title=u"Yuanoung Blog",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules=ui_modules,
            xsrf_cookies=True,
            cookie_secret="K71U8DBPNE-eyJsaWNlbnNlSWQiOiJLNVOERCUE5FIiwibGljZW5zZWVOYW1lIjoibGFuIHl1IiwiNzaWduZWVOYW1lIjoiIiwiYXNzaWduZWVFbWFpbCI6IiIsImxpY2Vuc2VSZXN0cmljdGlvbiI6IkZvciBlZHVjYXRpb25hbCB1c2Ugb25seSIsImNoZWNrQ29uY3VycmVudFVzZSI6ZmFsc2UsInByb2R1Y3RzIjpbeyJjb2RlIjoiSUkiLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJSUzAiLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJXUyIsInBhaWRVcFRvIjoiMjAxOS0wNS0wNCJ9LHsiY29kZSI6IlJEIiwicGFpZFVwVG8iOiIyMDE5LTA1LTA0In0seyJjb2RlIjoiUkMiLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJEQyIsInBhaWRVcFRvIjoiMjAxOS0wNS0wNCJ9LHsiY29kZSI6IkRCIiwicGFpZFVwVG8iOiIyMDE5LTA1LTA0In0seyJjb2RlIjoiUk0iLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJETSIsInBhaWRVcFRvIjoiMjAxOS0wNS0wNCJ9LHsiY29kZSI6IkFDIiwicGFpZFVwVG8iOiIyMDE5LTA1LTA0In0seyJjb2RlIjoiRFBOIiwicGFpZFVwVG8iOiIyMDE5LTA1LTA0In0seyJjb2RlIjoiR08iLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJQUyIsInBhaWRVcFRvIjoiMjAxOS0wNS0wNCJ9LHsiY29kZSI6IkNMIiwicGFpZFVwVG8iOiIyMDE5LTA1LTA0In0seyJjb2RlIjoiUEMiLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifSx7ImNvZGUiOiJSU1UiLCJwYWlkVXBUbyI6IjIwMTktMDUtMDQifV0sImhhc2giOiI4OTA4Mjg5LzAiLCJncmFjZVBlcmlvZERheXMiOjAsImF1dG9Qcm9b25nYXRlZCI6ZmFsc2UsImlzQXV0b1Byb2xvbmdhdGVkIjYWxzZX0=-Owt3/+LdCpedvF0eQ8635yYt0+ZLtCfIHOKzSrx5hBbKGYRPFDrdgQAK6lJjexl2emLBcUq729K1+ukY9Js0nx1NH09l9Rw4c7k9wUksLl6RWx7Hcdcma1AHolfSp79NynSMZzQQLFohNyjD+dXfXM5GYd2OTHya0zYjTNMmAJuuRsapJMP9F1z7UTpMpLMxS/JaCWdyX6qIs+funJdPF7bjzYAQBvtbz+6SANBgN36gG1B2xHhccTn6WE8vagwwSNuM70egpahcTktoHxI7uS1JGN9gKAr6nbp+8DbFz3a2wd+XoF3nSJb/d2f/6zJR8yJF8AOyb30kwg3zf5cWw==-MIIEPjCCAiagAwIBAgIBBTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1KZXRQcm9maWxlIENBMB4XDTE1MTEwMjA4MjE0OFoXDTE4MTEwMTA4MjE0OFowETEPMA0GA1UEAwwGcHJvZDN5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcQkq+zdxlR2mmRYBPzGbUNdMN6OaXiXzxIWtMEkrJMO/5oUfQJbLLuMSMK0QHFmaI37WShyxZcfRCidwXjot4zmNBKnlyHodDij/78TmVqFl8nOeD5+07B8VEaIu7c3E1N+e1doC6wht4I4+IEmtsPAdoaj5WCQVQbrI8KeT8M9VcBIWX7fD0fhexfg3ZRt0xqwMcXGNp3DdJHiO0rCdU+Itv7EmtnSVq9jBG1usMSFvMowR25mju2JcPFp1+I4ZI+FqgR8gyG8oiNDyNEoAbsR3lOpI7grUYSvkB/xVy/VoklPCK2h0f0GJxFjnye8NT1PAywoyl7RmiAVRE/EKwIDAQABo4GZMIGWMAkGA1UdEwQCMAAwHQYDVR0OBBYEFGEpG9oZGcfLMGNBkY7SgHiMGgTcMEgGA1UdIwRBMD+AFKOetkhnQhI2Qb1t4Lm0oFKLl/GzoRykGjAYMRYwFAYDVQQDDA1KZXRQcm9maWxlIENBggkA0myxg7KDeeEwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQC9WZuYgQedSuOc5TOUSrRigMw4/+wuC5EtZBfvdl4HT/8vzMW/oUlIP4YCvA0XKyBaCJ2iX+ZCDKoPfiYXiaSiH+HxAPV6J79vvouxKrWg2XV6ShFtPLP+0gPdGq3x9R3+kJbmAm8w+FOdlWqAfJrLvpzMGNeDU14YGXiZ9bVzmIQbwrBA+c/F4tlK/DV07dsNExihqFoibnqDiVNTGombaU2dDup2gwKdL81ua8EIcGNExHe82kjF4zwfadHk3bQVvbfdAwxcDy4xBjs3L4raPLU3yenSzr/OEur1+jfOxnQSmEcMXKXgrAQ9U55gwjcOFKrgOxEdek/Sk1VfOjvS+nuM4eyEruFMfaZHzoQiuw4IqgGc45ohFH0UUyjYcuFxxDSU9lMCv8qdHKm+wnPRb0l9l5vXsCBDuhAGYD6ss+Ga+aDY6f/qXZuUCEUOH3QUNbbCUlviSz6+GiRnt1kA9N2Qachl+2yBfaqUqr8h7Z2gsx5LcIf5kYNsqJvXTVyWh7PYiKX4bs354ZQLUwwa/cG++2+wNWP+HtBhVxMRNTdVhSm38AknZlD+PTAsWGu9GyLmhti2EnVwGybSD2Dxmhxk3IPCkhKAK+pl0eWYGZWG3tJ9mZ7SowcXLWDFAk0lRJnKGFMTggrWjV8GYpw5bq23VmIqqDLgkNzuoog==",
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    async def execute(self, stmt, *args):
        """Execute a SQL statement.

        Must be called with ``await self.execute(...)``
        """
        with (await self.application.db) as conn:
            cur = await conn.cursor()
            await cur.execute(stmt, args)

    async def query(self, stmt, *args):
        """Query for a list of results.

        Typical usage::

            results = await self.query(...)

        Or::

            for row in await self.query(...)
        """
        with (await self.application.db) as conn:
            cur = await conn.cursor(AttrDictCursor)
            await cur.execute(stmt, args)
            r = await cur.fetchall()
            return r

    async def insert(self, stmt, *args):
        with (await  self.application.db) as conn:
            cur = await conn.cursor()
            await cur.execute(stmt, args)
            return cur.lastrowid

    async def insertmany(self, stmt, *args):
        with (await self.application.db) as conn:
            cur = await conn.cursor()
            await cur.executemany(stmt, args)

    async def queryone(self, stmt, *args):
        """Query for exactly one result.

        Raises NoResultError if there are no results, or ValueError if
        there are more than one.
        """
        results = await self.query(stmt, *args)
        if len(results) == 0:
            raise NoResultError()
        elif len(results) > 1:
            raise ValueError("Expected 1 result, got %d" % len(results))
        return results[0]

    async def prepare(self):
        # get_current_user cannot be a coroutine, so set
        # self.current_user in prepare instead.
        user_id = self.get_secure_cookie("blogdemo_user")
        if user_id:
            self.current_user = await self.queryone(
                "SELECT * FROM authors WHERE id = %s", int(user_id)
            )

    async def any_author_exists(self):
        return bool(await self.query("SELECT * FROM authors LIMIT 1"))


class HomeHandler(BaseHandler):
    page_size = 20

    async def get(self):
        title = self.get_argument("title", None)
        category = self.get_argument("category", None)
        page = int(self.get_argument("page", 0))
        offset = self.page_size * page

        with (await self.application.db) as conn:
            cur = await conn.cursor(AttrDictCursor)
            await cur.execute("SELECT DISTINCT category FROM articles")
            r = await cur.fetchall()
            categories = [value["category"] for value in r]

            if title and category:
                args = (
                    "SELECT id, title, published, abstract, category FROM articles where category = %s, title like %s ORDER BY published DESC LIMIT %s,%s",
                    (category, "%" + title + "%", offset, self.page_size))
            elif title:
                args = (
                    "SELECT id, title, published, abstract, category FROM articles where title like %s ORDER BY published DESC LIMIT %s,%s",
                    ("%" + title + "%", offset, self.page_size))
            elif category:
                args = (
                    "SELECT id, title, published, abstract, category FROM articles where category = %s ORDER BY published DESC LIMIT %s,%s",
                    (category, offset, self.page_size))
            else:
                args = (
                    "SELECT id, title, published, abstract, category FROM articles ORDER BY published DESC LIMIT %s,%s",
                    (offset, self.page_size))
            await cur.execute(*args)
            articles = await cur.fetchall()

        if not articles:
            return
        next_url = None
        if not page:
            self.render("home.html", articles=articles, next_url=next_url, categories=categories)
        else:
            data = self.render_string("more_article_post_card.html", articles=articles)
            self.write(data)


class FeedHandler(BaseHandler):
    async def get(self):
        entries = await self.query(
            "SELECT * FROM entries ORDER BY published DESC LIMIT 10"
        )
        self.set_header("Content-Type", "application/atom+xml")
        self.render("feed.xml", entries=entries)


class ArticleSaveHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self):
        article_id = self.get_argument("article_id")
        title = unquote(self.get_argument("title"))
        markdowncontent = unquote(self.get_argument("markdowncontent"))
        abstract = ''.join(r.group() for r in re.finditer('\w+', markdowncontent, flags=re.M))[:188]
        content = tornado.escape.xhtml_escape(unquote(self.get_argument("content")))
        category = unquote(self.get_argument("categories"))

        if article_id:
            await self.execute(
                "UPDATE articles SET title=%s, content=%s, markdowncontent=%s, category=%s, abstract=%s, updated=%s where id=%s",
                title,
                content,
                markdowncontent,
                category,
                abstract,
                datetime.now(),
                article_id
            )
        else:
            await self.insert(
                "INSERT INTO articles (author_id,title,markdowncontent,content,category,abstract,published,updated)"
                "VALUES (%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                self.current_user.id,
                title,
                markdowncontent,
                content,
                category,
                abstract
            )
        self.redirect("/")


class ArticleDetailHandler(BaseHandler):
    async def get(self, article_id):
        with (await self.application.db) as conn:
            cur = await conn.cursor(AttrDictCursor)
            await cur.execute("SELECT DISTINCT category FROM articles")
            r = await cur.fetchall()
            categories = [value["category"] for value in r]
            await cur.execute("SELECT * FROM articles where id = %s", article_id)
            r = await cur.fetchall()
            if r:
                article = r[0]
            await cur.execute("UPDATE articles SET click=click+1 where id=%s", article_id)
        article["content"] = html.unescape(article["content"])
        self.render("article_detail.html", article=article, categories=categories)


class ArticleEditHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        article_id = self.get_argument("article_id")
        content = await self.queryone("SELECT title, content, markdowncontent, category FROM articles where id = %s",
                                      article_id)
        self.finish({
            "data": content,
            "status": True,
            "error": "",
        })


class CreateHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        article_id = self.get_argument("article_id", None)
        self.render("create_article.html", article_id=article_id)


class AuthCreateHandler(BaseHandler):
    def get(self):
        if self.any_author_exists():
            return
        self.render("create_author.html")

    async def post(self):
        if await self.any_author_exists():
            raise tornado.web.HTTPError(400, "author already created")
        hashed_password = await tornado.ioloop.IOLoop.current().run_in_executor(
            None,
            bcrypt.hashpw,
            tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt(),
        )
        author = await self.insert(
            "INSERT INTO authors (email, name, hashed_password) "
            "VALUES (%s, %s, %s)",
            self.get_argument("email"),
            self.get_argument("name"),
            tornado.escape.to_unicode(hashed_password),
        )
        self.set_secure_cookie("blogdemo_user", str(author))
        self.redirect(self.get_argument("next", "/"))


class AuthLoginHandler(BaseHandler):
    async def get(self):
        # If there are no authors, redirect to the account creation page.
        if not await self.any_author_exists():
            self.redirect("/auth/create")
        else:
            self.render("login.html", error=None, next_url=self.request.uri)

    async def post(self):
        try:
            author = await self.queryone(
                "SELECT * FROM authors WHERE email = %s", self.get_argument("email")
            )
        except NoResultError:
            self.render("login.html", error="email not found")
            return
        hashed_password = await tornado.ioloop.IOLoop.current().run_in_executor(
            None,
            bcrypt.hashpw,
            tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(author.hashed_password),
        )
        hashed_password = tornado.escape.to_unicode(hashed_password)
        if hashed_password == author.hashed_password:
            self.set_secure_cookie("blogdemo_user", str(author.id))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("blogdemo_user")
        self.redirect(self.get_argument("next", "/"))


async def main():
    tornado.options.parse_command_line()

    # Create the global connection pool.
    async with aiomysql.create_pool(
            maxsize=256,
            host=options.db_host,
            port=options.db_port,
            user=options.db_user,
            password=options.db_password,
            db=options.db_database,
            autocommit=True,
    ) as db:
        # await maybe_create_tables(db)
        app = Application(db)
        app.listen(options.port)

        # In this demo the server will simply run until interrupted
        # with Ctrl-C, but if you want to shut down more gracefully,
        # call shutdown_event.set().
        shutdown_event = tornado.locks.Event()
        await shutdown_event.wait()


if __name__ == "__main__":
    tornado.ioloop.IOLoop.current().run_sync(main)
