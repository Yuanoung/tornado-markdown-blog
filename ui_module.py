#!/usr/bin/env python3
import tornado.web


class ArticleModule(tornado.web.UIModule):
    def render(self, article):
        return self.render_string("modules/article.html", article=article)


class ArticleDetailModule(tornado.web.UIModule):
    def render(self, article):
        return self.render_string("modules/detail.html", article=article)


class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)


ui_modules = {"Entry": EntryModule,
              "Article": ArticleModule,
              "ArticleDetail": ArticleDetailModule}
