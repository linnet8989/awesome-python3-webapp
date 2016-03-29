#!/usr/bin/env python3
# -*- coding: utf-8 -*-

' url handlers '

import re, time, json, logging, hashlib, base64, asyncio

import markdown2

from aiohttp import web

from coroweb import get, post
from apis import Page, APIValueError, APIResourceNotFoundError

from models import User, Comment, Item, next_id
from config import configs

COOKIE_NAME = 'awesession'
_COOKIE_KEY = configs.session.secret

def check_admin(request):
    if request.__user__ is None or not request.__user__.admin:
        raise APIPermissionError()

def check_permission(request, id=None, user_id=None):
    if id:
        item = yield from Item.find(id)
        if item:
            if request.__user__ is None or not request.__user__.publisher or request.__user__.id != item.user_id:
                check_admin(request)
    elif user_id:
        if request.__user__ is None or request.__user__.id != user_id:
            check_admin(request)
    elif request.__user__ is None or not request.__user__.publisher:
        check_admin(request)

def get_page_index(page_str):
    p = 1
    try:
        p = int(page_str)
    except ValueError as e:
        pass
    if p < 1:
        p = 1
    return p

def user2cookie(user, max_age):
    '''
    Generate cookie str by user.
    '''
    # build cookie string by: id-expires-sha1
    expires = str(int(time.time() + max_age))
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    return '-'.join(L)

def text2html(text):
    lines = map(lambda s: '<p>%s</p>' % s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'), filter(lambda s: s.strip() != '', text.split('\n')))
    return ''.join(lines)

@asyncio.coroutine
def cookie2user(cookie_str):
    '''
    Parse cookie and load user if cookie is valid.
    '''
    if not cookie_str:
        return None
    try:
        L = cookie_str.split('-')
        if len(L) != 3:
            return None
        uid, expires, sha1 = L
        if int(expires) < time.time():
            return None
        user = yield from User.find(uid)
        if user is None:
            return None
        s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
        if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
            logging.info('invalid sha1')
            return None
        user.passwd = '******'
        return user
    except Exception as e:
        logging.exception(e)
        return None

@get('/')
def index(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Item.findNumber('count(id)')
    page = Page(num)
    if num == 0:
        items = []
    else:
        items = yield from Item.findAll(orderBy='created_at desc', limit=(page.offset, page.limit))
    return {
        '__template__': 'items.html',
        'page': page,
        'items': items
    }

@get('/item/{id}')
def get_item(id):
    item = yield from Item.find(id)
    comments = yield from Comment.findAll('item_id=?', [id], orderBy='created_at desc')
    for c in comments:
        c.html_content = text2html(c.content)
    item.html_content = markdown2.markdown(item.content)
    return {
        '__template__': 'item.html',
        'item': item,
        'comments': comments
    }

@get('/register')
def register():
    return {
        '__template__': 'register.html'
    }

@get('/signin')
def signin():
    return {
        '__template__': 'signin.html'
    }

@post('/api/authenticate')
def authenticate(*, email, passwd):
    if not email:
        raise APIValueError('email', 'Invalid email.')
    if not passwd:
        raise APIValueError('passwd', 'Invalid password.')
    users = yield from User.findAll('email=?', [email])
    if len(users) == 0:
        raise APIValueError('email', 'Email not exist.')
    user = users[0]
    # check passwd:
    sha1 = hashlib.sha1()
    sha1.update(user.id.encode('utf-8'))
    sha1.update(b':')
    sha1.update(passwd.encode('utf-8'))
    if user.passwd != sha1.hexdigest():
        raise APIValueError('passwd', 'Invalid password.')
    # authenticate ok, set cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

@get('/signout')
def signout(request):
    referer = request.headers.get('Referer')
    r = web.HTTPFound(referer or '/')
    r.set_cookie(COOKIE_NAME, '-deleted-', max_age=0, httponly=True)
    logging.info('user signed out.')
    return r

@get('/manage/')
def manage():
    return 'redirect:/manage/comments'

@get('/manage/comments')
def manage_comments(*, page='1'):
    return {
        '__template__': 'manage_comments.html',
        'page_index': get_page_index(page)
    }

@get('/manage/items')
def manage_items(*, page='1'):
    return {
        '__template__': 'manage_items.html',
        'page_index': get_page_index(page)
    }

# New URL
@get('/manage/user/{user_id}/items')
def manage_user_items(user_id, *, page='1'):
    return {
        '__template__': 'manage_user_items.html',
        'user_id': user_id,
        'page_index': get_page_index(page)
    }

@get('/manage/items/create')
def manage_create_item():
    return {
        '__template__': 'manage_item_edit.html',
        'id': '',
        'action': '/api/items'
    }

# New URL
@get('/manage/user/{user_id}/items/create')
def manage_user_create_item(user_id):
    return {
        '__template__': 'manage_user_item_edit.html',
        'id': '',
        'user_id': user_id,
        'action': '/api/items'
    }

@get('/manage/items/edit')
def manage_edit_item(*, id):
    return {
        '__template__': 'manage_item_edit.html',
        'id': id,
        'action': '/api/items/%s' % id
    }

# New URL
@get('/manage/user/{user_id}/items/edit')
def manage_user_edit_item(user_id, *, id):
    return {
        '__template__': 'manage_user_item_edit.html',
        'id': id,
        'user_id': user_id,
        'action': '/api/items/%s' % id
    }

@get('/manage/users')
def manage_users(*, page='1'):
    return {
        '__template__': 'manage_users.html',
        'page_index': get_page_index(page)
    }

# New URL
@get('/manage/user/{user_id}')
def manage_user(user_id):
    user = yield from User.find(user_id)
    return {
        '__template__': 'manage_user.html',
        'user_id': user_id,
        'email': user.email
    }

@get('/api/comments')
def api_comments(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Comment.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, comments=())
    comments = yield from Comment.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, comments=comments)

@post('/api/items/{id}/comments')
def api_create_comment(id, request, *, content):
    user = request.__user__
    if user is None:
        raise APIPermissionError('Please signin first.')
    if not content or not content.strip():
        raise APIValueError('content')
    item = yield from Item.find(id)
    if item is None:
        raise APIResourceNotFoundError('Item')
    comment = Comment(item_id=item.id, user_id=user.id, user_name=user.name, user_image=user.image, content=content.strip())
    yield from comment.save()
    return comment

@post('/api/comments/{id}/delete')
def api_delete_comments(id, request):
    check_admin(request)
    c = yield from Comment.find(id)
    if c is None:
        raise APIResourceNotFoundError('Comment')
    yield from c.remove()
    return dict(id=id)

@get('/api/users')
def api_get_users(*, page='1'):
    page_index = get_page_index(page)
    num = yield from User.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, users=())
    users = yield from User.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    for u in users:
        u.passwd = '******'
    return dict(page=p, users=users)

_RE_EMAIL = re.compile(r'^[a-z0-9\.\-\_]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')

@post('/api/users')
def api_register_user(*, email, name, passwd, contact):
    if not name or not name.strip():
        raise APIValueError('name')
    if not email or not _RE_EMAIL.match(email):
        raise APIValueError('email')
    if not passwd or not _RE_SHA1.match(passwd):
        raise APIValueError('passwd')
    publisher = True if contact.strip() else False
    users = yield from User.findAll('email=?', [email])
    if len(users) > 0:
        raise APIError('register:failed', 'email', 'Email is already in use.')
    uid = next_id()
    sha1_passwd = '%s:%s' % (uid, passwd)
    user = User(id=uid, name=name.strip(), email=email, passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(), contact=contact.strip(), publisher=publisher, image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode('utf-8')).hexdigest())
    yield from user.save()
    # make session cookie:
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '******'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

# New API
@post('/api/users/{user_id}')
def api_update_user(user_id, request, *, name, passwd, contact):
    check_permission(request, user_id=user_id)
    if not name or not name.strip():
        raise APIValueError('name')
    if not passwd or not _RE_SHA1.match(passwd):
        raise APIValueError('passwd')
    user = yield from User.find(user_id)
    if len(user) > 0:
        user.name = name.strip()
        sha1_passwd = '%s:%s' % (user.id, passwd)
        user.passwd = hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest()
        user.contact = contact.strip()
        user.publisher = True if contact.strip() else False
        user.image = 'http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(user.email.encode('utf-8')).hexdigest()
        yield from user.update()
        r = web.Response()
        r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
        user.passwd = '******'
        r.content_type = 'application/json'
        r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
        return r

@get('/api/items')
def api_items(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Item.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, items=())
    items = yield from Item.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, items=items)

# New API
@get('/api/user/{user_id}/items')
def api_user_items(*, page='1', user_id):
    page_index = get_page_index(page)
    num = yield from Item.findNumber('count(id)', 'user_id=?', [user_id])
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, items=())
    items = yield from Item.findAll('user_id=?', [user_id], orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, items=items)

@get('/api/items/{id}')
def api_get_item(*, id):
    item = yield from Item.find(id)
    return item

@post('/api/items')
def api_create_item(request, *, name, content, contact, price, num):
    check_permission(request)
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    if not contact or not contact.strip():
        raise APIValueError('contact', 'contact cannot be empty.')
    if price < 0:
        raise APIValueError('price', 'price cannot be negative.')
    if num < 0:
        raise APIValueError('num', 'number cannot be negative.')
    item = Item(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, name=name.strip(), content=content.strip(), contact=contact.strip(), price=price, num=num)
    yield from item.save()
    return item

@post('/api/items/{id}')
def api_update_item(id, request, *, name, content, contact, price, num):
    check_permission(request, id)
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    if not contact or not contact.strip():
        raise APIValueError('contact', 'contact cannot be empty.')
    if price < 0:
        raise APIValueError('price', 'price cannot be negative.')
    if num < 0:
        raise APIValueError('num', 'number cannot be negative.')
    item.name = name.strip()
    item.summary = summary.strip()
    item.content = content.strip()
    item.price = price
    item.num = num
    yield from item.update()
    return item

@post('/api/items/{id}/delete')
def api_delete_item(request, *, id):
    check_permission(request, id)
    item = yield from Item.find(id)
    yield from item.remove()
    return dict(id=id)
