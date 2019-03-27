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
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
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
    page_size = 10

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
                args = ("SELECT * FROM articles where category = %s, title like %s ORDER BY published DESC LIMIT %s,%s",
                        (category, "%" + title + "%", offset, self.page_size))
            elif title:
                args = ("SELECT * FROM articles where title like %s ORDER BY published DESC LIMIT %s,%s",
                        ("%" + title + "%", offset, self.page_size))
            elif category:
                args = ("SELECT * FROM articles where category = %s ORDER BY published DESC LIMIT %s,%s",
                        (category, offset, self.page_size))
            else:
                args = ("SELECT * FROM articles ORDER BY published DESC LIMIT %s,%s",
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
        content = tornado.escape.xhtml_escape(unquote(self.get_argument("content")))
        category = unquote(self.get_argument("categories"))

        if article_id:
            await self.execute(
                "UPDATE articles SET title=%s, content=%s, markdowncontent=%s, category=%s, updated=%s where id=%s",
                title,
                content,
                markdowncontent,
                category,
                datetime.now(),
                article_id
            )
        else:
            await self.insert(
                "INSERT INTO articles (author_id,title,markdowncontent,content,category,published,updated)"
                "VALUES (%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                self.current_user.id,
                title,
                markdowncontent,
                content,
                category
            )
        self.redirect("/")


class ArticleDetailHandler(BaseHandler):
    async def get(self, article_id):
        categorise = ["aaa", "bbb", "ccc"]  # todo
        article = await self.queryone("SELECT * FROM articles where id = %s", article_id)
        article["content"] = html.unescape(article["content"])
        self.render("article_detail.html", article=article, categories=categorise)


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
        print("server is runing...")

        # In this demo the server will simply run until interrupted
        # with Ctrl-C, but if you want to shut down more gracefully,
        # call shutdown_event.set().
        shutdown_event = tornado.locks.Event()
        await shutdown_event.wait()


if __name__ == "__main__":
    tornado.ioloop.IOLoop.current().run_sync(main)
