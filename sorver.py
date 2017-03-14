#!/usr/bin/python3

from http import server, cookies
import html
import urllib
import sqlite3
import hashlib
import uuid
import re
import time
import base64
import os
import sys
import traceback
import mimetypes

import check

root_pwd_hash = 'ba08da735b2350af9a26c6bd27a8825d3a178e199d5a6b2a2fce93619461'\
                '017c233c1f55f0aab8dc530db3e52ca2779e933d897ab9fdcbcc5be18d51'\
                '63b38491'

log_file = open('log.txt', 'ab')

conn = sqlite3.connect('users.db')
c = conn.cursor()
c.executescript('''
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    hash TEXT,
    salt TEXT,
    level INTEGER
);
CREATE TABLE IF NOT EXISTS Sessions (
    id INTEGER PRIMARY KEY,
    userid INTEGER,
    cookie TEXT
);
CREATE TABLE IF NOT EXISTS Keys (
    id INTEGER PRIMARY KEY,
    key TEXT,
    username TEXT
);
CREATE TABLE IF NOT EXISTS Guesses (
    id INTEGER PRIMARY KEY,
    userid INTEGER,
    level INTEGER,
    guess TEXT,
    solved BOOLEAN,
    tstamp INTEGER
);
''')
conn.commit()

htmldata = {}
for s in os.listdir('html'):
    with open('html/{}'.format(s)) as f:
        htmldata[s[:-5]] = f.read()

static = {}
for (parent, dirs, files) in os.walk('static'):
    for fname in files:
        fname = os.path.join(parent, fname)
        with open(fname, 'rb') as f:
            static[fname[6:]] = (f.read(), mimetypes.guess_type(fname)[0])

def userinfo_html(uid, username):
    if uid:
        return '''
        <div id='userinfo'>
            logged in as <a href='/u{}'>{}</a>
        </div>
        '''.format(uid, html.escape(username))
    else:
        return ''

def user_html(uid, username):
    return '''
    <h2>user <em>''' + html.escape(username) + '''</em></h2>
    <ul>
    ''' + ('\n'.join(
        '<li>solved level {} on {}</li>'.format(
            sltn[0],
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sltn[1]))
        ) for sltn in c.execute('''
            SELECT level, tstamp
            FROM Guesses
            WHERE userid = ? AND solved = 1
            ORDER BY level DESC
            ''', (uid,)).fetchall()
    ) or '<li>no puzzles solved yet</li>') + '''
    </ul>
    '''

def userlist_html():
    return '''
    <h2>users</h2>
    <p>sorted by ranking, highest level first. people who reached a level
       earlier are ranked higher. users who have not completed level 1 are
       not listed.</p>
    <ol>
    ''' + '\n'.join(
        ('<li><strong><a href=\'/u{}\'>{}</a></strong> '\
                '(reached level {} on {})</li>').format(
            user[0],
            user[1],
            user[2],
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user[3]))
        ) for user in c.execute('''
            SELECT u.id, u.username, u.level, g.tstamp
            FROM Users u
            JOIN Guesses g ON u.id = g.userid
            WHERE g.solved = 1 AND (SELECT COUNT(*)
                FROM Guesses g2
                WHERE g2.solved = 1
                  AND g2.userid = g.userid
                  AND g2.level > g.level
                ) == 0
            ORDER BY u.level DESC, g.tstamp ASC
            ''').fetchall()
    ) + '''
    </ol>
    '''

def guesses_html(uid, level):
    guesses = '\n'.join(
        '<li><strong>{}</strong> on {}</li>'.format(
            guess[0],
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(guess[1]))
        ) for guess in c.execute('''
            SELECT guess, tstamp
            FROM Guesses
            WHERE userid = ? AND level = ?
            ORDER BY tstamp DESC
            ''', (uid, level)).fetchall()
    )
    if guesses:
        return '''
        <p>previous guesses:</p>
        <ul>{}</ul>
        '''.format(guesses)
    else:
        return ''

class Handler(server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path in static:
            self.send_response(200)
            self.send_header('Content-Type', static[self.path][1])
            self.send_header('Content-Length', len(static[self.path][0]))
            self.end_headers()
            self.wfile.write(static[self.path][0])
            return

        (cookie, uid, username, level) = self.uinfo()

        main_html = None
        if re.fullmatch(r'/u\d+', self.path):
            puid = int(self.path[2:])
            pusername = c.execute('SELECT username FROM Users WHERE id = ?',
                    (puid,)).fetchone()
            if pusername:
                main_html = user_html(puid, pusername[0])
        elif self.path == '/users':
            main_html = userlist_html()
        elif re.fullmatch(r'/r[A-Za-z0-9_-]*=*', self.path):
            try:
                txt = base64.urlsafe_b64decode(self.path[2:].encode()).decode()
                main_html = html.escape(txt)
            except (base64.binascii.Error, UnicodeDecodeError):
                pass
        elif self.path in ['/info', '/db']:
            main_html = htmldata[self.path[1:]]
        elif self.path == '/':
            if level:
                main_html = htmldata['level' + str(level)] \
                        + guesses_html(uid, level)
            else:
                main_html = htmldata['login']

        data = htmldata['base'] \
                .replace('[[userinfo]]', userinfo_html(uid, username)) \
                .replace('[[main]]', main_html or htmldata['404']) \
                .replace('[[path]]', self.path) \
                .replace('[[username]]', str(username)) \
                .encode()

        self.send_response(200 if main_html else 404)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(data))
        if str(cookie):
            self.flush_headers()
            self.wfile.write(cookie.output().encode() + b'\r\n')
        self.end_headers()

        self.wfile.write(data)

    def do_POST(self):
        resp = None

        # e[x]isting information
        (cookie, xuid, xusername, xlevel) = self.uinfo()

        qs = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        qs = urllib.parse.parse_qs(qs.decode())
        loginid = None

        if 'login' in qs and 'username' in qs and 'password' in qs:
            loginid = self.login(qs['username'][0], qs['password'][0])
        elif 'register' in qs and 'key' in qs and 'rpassword' in qs:
            loginid = self.register(qs['key'][0], qs['rpassword'][0])
        elif 'dbquery' in qs and 'password' in qs:
            if hashlib.sha512(qs['password'][0]).hexdigest() == root_pwd_hash:
                resp = repr(c.execute(qs['dbquery'][0]).fetchall())
                conn.commit()
            else:
                resp = 'wrong password'
        elif xlevel:
            param = 'answer' + str(xlevel)
            if param in qs:
                resp = self.guess(xuid, xlevel, qs[param][0])

        sid = None
        if loginid:
            sid = uuid.uuid4().hex
            c.execute('INSERT INTO Sessions (userid, cookie) VALUES (?, ?)',
                    (loginid, sid))
            conn.commit()

        self.send_response(302)

        if sid: self.send_header('Set-Cookie', 'session={}'.format(sid))

        if resp: self.send_header('Location', '/r' +
                base64.urlsafe_b64encode(resp.encode()).decode())
        else: self.send_header('Location', '/')

        self.end_headers()

    def uinfo(self):
        uid, username, level = None, None, None
        cookie = cookies.SimpleCookie()
        if self.headers.get('Cookie'):
            cookie.load(self.headers.get('Cookie'))
            if 'session' in cookie:
                vals = c.execute('''
                        SELECT u.id, u.username, u.level
                        FROM Users u
                        LEFT JOIN Sessions
                        WHERE u.id = userid AND cookie = ?
                        ''', (cookie['session'].value,)).fetchone()
                if vals:
                    uid, username, level = vals
        return (cookie, uid, username, level)

    def login(self, username, password):
        vals = c.execute('SELECT id, salt, hash FROM Users WHERE username = ?',
                (username,)).fetchone()
        if vals:
            uid, salt, hsh = vals
            if hsh == hashlib.sha512((salt + password).encode()).hexdigest():
                return uid

    def register(self, key, password):
        username = c.execute('SELECT username FROM Keys WHERE key = ?',
                (key,)).fetchone()
        if username and len(password) > 0:
            username = username[0]
            salt = uuid.uuid4().hex
            hsh = hashlib.sha512((salt + password).encode()).hexdigest()
            c.execute('DELETE FROM Keys WHERE key = ?', (key,))
            c.execute('''
                    INSERT INTO Users (username, hash, salt, level)
                    VALUES (?, ?, ?, 1)
                    ''', (username, hsh, salt))
            conn.commit()
            return c.execute('SELECT last_insert_rowid()').fetchone()[0]

    def guess(self, uid, level, txt):
        last_guess = c.execute('''
                SELECT tstamp
                FROM Guesses
                WHERE userid = ? AND level = ?
                ORDER BY tstamp DESC
                LIMIT 1
                ''', (uid, level)).fetchone()

        if last_guess and time.time() - last_guess[0] < 60:
            return 'you must wait at least a minute between guesses.'
        else:
            solved = getattr(check, 'check' + str(level))(txt)
            c.execute('''
                    INSERT INTO Guesses (userid, level, guess, solved, tstamp)
                    VALUES (?, ?, ?, ?, ?)
                    ''',
                    (uid, level, txt, 1 if solved else 0, int(time.time())))
            if solved:
                c.execute('UPDATE Users SET level = ? WHERE id = ?',
                        (level + 1, uid))
            conn.commit()

    def log_message(self, fmt, *args):
        msg = "{} - - [{}] {}\n".format(
                self.client_address[0],
                self.log_date_time_string(),
                fmt % args)
        log_file.write(msg.encode())
        log_file.flush()
        sys.stderr.write(msg)
        sys.stderr.flush()

class Server(server.HTTPServer):
    def handle_error(self, request, client_address):
        msg = '-' * 40 + \
                '\nException happened during processing of request from ' + \
                str(client_address) + '\n' + traceback.format_exc() + \
                '-' * 40 + '\n'
        log_file.write(msg.encode())
        log_file.flush()
        sys.stderr.write(msg)
        sys.stderr.flush()

Server(('', 80), Handler).serve_forever()
