import os
import webapp2
import jinja2
import hmac
import re
import hashlib
import urllib2
import json
import logging
import time
from xml.dom import minidom

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = 'sanketnpri'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=850x250&sensor=false&"
def gmaps_img(points):
    markers = '&'.join('markers=%s,%s' % (p.lat, p.lon)
                       for p in points)
    return GMAPS_URL + markers

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except:
        return
    
    if content:
        d = minidom.parseString(content)
        coords = d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon, lat = coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat, lon)
        
class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))
        
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
class BlogDB(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty() 

class UsersDB(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

def top_posts(update = False):
    key = 'top'
    contents = memcache.get(key)
    if contents is None or update:
        logging.error("DB QUERY")
        contents = db.GqlQuery("SELECT * FROM BlogDB ORDER BY created DESC")
        contents = list(contents)
        memcache.set(key, contents)
        memcache.set('time', time.time())
    return contents
                    
class Blog(BaseHandler):
    def render_index(self):
        #contents = db.GqlQuery("SELECT * FROM BlogDB ORDER BY created DESC")
        #contents = list(contents)
        contents = top_posts()
        if self.request.url.endswith('.json'):
            jsonString = []
            for entry in contents:
                this = {}
                this['subject'] = entry.subject
                this['content'] = entry.content
                this['created'] = entry.created.strftime('%c')
                jsonString.append(this)
            jsonString = json.dumps(jsonString)
            self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
            self.write(jsonString)
        else:
            points = filter(None, (a.coords for a in contents))
            img_url = None
            if points:
                img_url = gmaps_img(points)
            
            visits = 0
            visit_cookie_str = self.request.cookies.get('visits')
            if visit_cookie_str:
                cookie_val = check_secure_val(visit_cookie_str)
                if cookie_val:
                    visits = int(cookie_val)
                    
            visits += 1
            if memcache.get('time'):
                age = int(time.time()-memcache.get('time'))
            else:
                age = 0
            new_cookie_val = make_secure_val(str(visits))
            self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
            if int(visits)>100:
                reward = "You're the best ever!"
            else:
                reward = ''
            self.render("index.html", contents=contents, visits=visits, reward=reward, img_url = img_url, age = age)
    
    def get(self):
        self.render_index()

class Permalink(Blog):
    def get(self, blog_id):
        post = memcache.get(blog_id)
        if post is None:
            post = BlogDB.get_by_id(int(blog_id))
            post = post
            memcache.set(blog_id, post)
            memcache.set(blog_id + 'time', time.time())
        if memcache.get('time'):
            age = int(time.time() - memcache.get(blog_id+'time'))
        else:
            age = 0
        if self.request.url.endswith('.json'):
            jsonString = {}
            jsonString['subject'] = post.subject
            jsonString['content'] = post.content
            jsonString['created'] = post.created.strftime('%c')
            jsonString = json.dumps(jsonString)
            self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
            self.write(jsonString)
        else:
            self.render("index.html", contents=[post], age = age)
            
class NewPost(BaseHandler):
    def render_page(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
    
    def get(self):
        self.render_page()
        
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        coords = get_coords(self.request.remote_addr)
        
        if subject and content:
            b = BlogDB(subject = subject, content=content)
            if coords:
                b.coords = coords
            b_key = b.put()
            self.redirect("/blog/%d" % b_key.id())
        else:
            self.render_page(subject=subject, content=content, error="cannot publish without a title and some content!")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
    def get(self):
        self.render("signup.html")
    
    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        u = db.GqlQuery('SELECT * FROM UsersDB WHERE username=:1', str(username))
        for i in u:
            if i.username==username:
                params['error_username'] = 'User already exists!'
                have_error = True
        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if email: 
            if not valid_email(email):
                params['error_email'] = "That's not a valid email."
                have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            u = UsersDB(username = username, password = hashlib.sha256(password).hexdigest(), email = email )
            u.put()
            self.response.headers.add_header('Set-Cookie', 'user=%s;Path=/' % str(username))
            self.redirect('/blog/welcome')
class Login(BaseHandler):
    def get(self):
        self.render('login.html')
        
    def post(self):
        flag = False
        username = self.request.get('username')
        password = self.request.get('password')
        u = db.GqlQuery("SELECT * FROM UsersDB WHERE username=:1", username)
        for i in u:
            if i.username == username and i.password == hashlib.sha256(password).hexdigest():
                flag = True
        if not flag:
            error = "Invalid Login!"
            self.render("login.html", error = error)
        else:
            self.response.headers.add_header('Set-Cookie', 'user=%s;Path=/' % str(username))
            self.redirect('/blog/welcome')

class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "user=;Path=/")
        self.redirect("/blog/signup")  

class Flush(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')

class GetJSONPage(BaseHandler):
    def get(self):
        contents = list(db.GqlQuery("SELECT * FROM BlogDB ORDER BY created DESC"))
        jsonString = []
        for entry in contents:
            this = {}
            this['subject'] = entry.subject
            this['content'] = entry.content
            jsonString.append(this)
        jsonString = json.dumps(jsonString)
        self.response.headers['Content-Type'] = "application/json"
        self.write(jsonString)

class GetJSONPermalink(BaseHandler):
    def get(self, post_id):
        post = BlogDB.get_by_id(int(post_id))
        jsonString = {}
        jsonString['subject'] = post.subject
        jsonString['content'] = post.content
        jsonString = json.dumps(jsonString)
        self.response.headers['Content-Type'] = "application/json"
        self.write(jsonString)
         
class Welcome(BaseHandler):
    def get(self):
        user = self.request.cookies.get('user')
        if not user:
            user = 'guest'
        self.render('welcome.html', user = user)
        
app = webapp2.WSGIApplication([('/blog/?(?:\.json)?', Blog),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/?(?:\.json)?', Permalink),
                               ('/blog/signup/?', Signup),
                               ('/blog/welcome/?', Welcome),
                               ('/blog/login/?', Login),
                               ('/blog/logout/?', Logout),
                               ('/blog/flush/?', Flush)],
                              debug=True)
        