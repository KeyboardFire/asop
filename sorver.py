#!/usr/bin/python3

from http import server, cookies
import socketserver
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
import pickle
import itertools
import subprocess

import check

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
CREATE TABLE IF NOT EXISTS UserData (
    id INTEGER PRIMARY KEY,
    userid INTEGER,
    level INTEGER,
    data BLOB
);
CREATE TABLE IF NOT EXISTS Messages (
    id INTEGER PRIMARY KEY,
    userid INTEGER,
    message TEXT,
    read BOOLEAN,
    tstamp INTEGER
);
''')
conn.commit()
conn.close()

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

def tfmt(n): return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(n))

def msgheader_html(c, uid):
    if uid:
        s = '<a href="/messages">[messages]</a>'
        msgcount = c.execute('''
                SELECT COUNT(*)
                FROM Messages
                WHERE userid = ? AND read = 0''', (uid,)).fetchone()
        if msgcount and msgcount[0] > 0:
            s += '<span class="msgbadge">{}</span>'.format(msgcount[0])
        return s
    else:
        return ''

def userinfo_html(uid, username):
    if uid:
        return '''
        <div id='userinfo'>
            logged in as <a href='/u{}'>{}</a>
        </div>
        '''.format(uid, html.escape(username))
    else:
        return ''

def user_html(c, uid, username):
    return '''
    <h2>user <em>''' + html.escape(username) + '''</em></h2>
    <ul>
    ''' + ('\n'.join(
        '<li>solved level {} on {}</li>'.format(
            sltn[0],
            tfmt(sltn[1])
        ) for sltn in c.execute('''
            SELECT level, tstamp
            FROM Guesses
            WHERE userid = ? AND solved = 1
            ORDER BY level DESC
            ''', (uid,)).fetchall()
    ) or '<li>no puzzles solved yet</li>') + '''
    </ul>
    '''

def userlist_html(c):
    if True: #time.time() - os.path.getmtime('static/graph.png') > 60 * 10:
        regraph(c)
    return '''
    <h2>users</h2>
    <p>sorted by ranking, highest level first. people who reached a level
       earlier are ranked higher. users who have not completed level 1 are
       not listed.</p>
    <a href='/graph.png'><img style='width:100%' src='/graph.png'></a>
    <ol>
    ''' + '\n'.join(
        ('<li><strong><a href=\'/u{}\'>{}</a></strong> '\
                '(reached level {} on {})</li>').format(
            user[0],
            user[1],
            user[2],
            tfmt(user[3])
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

def messages_html(c, uid, username):
    return '''
    <h2>messages for '''+username+'''</h2>
    <p>this is where you can receive messages from me. I can see your guesses,
       so if you're missing a rule or something similar, I'll be able to
       clarify it for you.</p>
    <p>if you want to contact me, you can do so via Telegram (@KeyboardFire) or
       email (<code>a@kbd.fi</code>).</p>
    <form class='beforemsg' action='/' method='post'>
        <input type='submit' name='markread' id='markread'
            value="mark all as read">
    </form>
    ''' + ('\n'.join(
        ('<div class="mcontainer"><div class="message {}">'
         '<span class="tstamp">{}</span>{}</div></div>').format(
            "read" if message[1] else "unread",
            tfmt(message[2]),
            message[0]
        ) for message in c.execute('''
            SELECT message, read, tstamp
            FROM Messages
            WHERE userid = ?
            ORDER BY tstamp DESC
            ''', (uid,)).fetchall()
    ) or '<p>no messages yet</p>')

def viewguess_html(c):
    return '''
    <table style='width:100%;border-collapse:collapse'>
    ''' + '\n'.join(
        ('<tr {}><td><a href="/u{}">{}</a> ({})</td><td>'
         '<pre style="white-space:pre-wrap;word-break:break-all">{}</pre>'
         '</td><td>{}</td></tr>').format(
            'style="background-color:#282828"' if guess[0] else '',
            guess[1],
            guess[2],
            guess[3],
            html.escape(guess[4]),
            time.strftime('%H:%M:%S', time.localtime(guess[5]))
        ) for guess in c.execute('''
            SELECT solved, userid, (
                    SELECT username
                    FROM Users u
                    WHERE u.id = g.userid
                ), level, guess, tstamp
            FROM Guesses g
            WHERE tstamp > strftime('%s', 'now', '-1 day')
            ORDER BY tstamp DESC''')
    ) + '''
    </table>
    '''

def guesses_html(c, uid, level):
    guesses = '\n'.join(
        '<li><strong>{}</strong> on {}</li>'.format(
            guess[0],
            tfmt(guess[1])
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

def regraph(c):
    now = int(time.time()) - 60*60*5
    with open('graph.dat', 'w') as f:
        for username, solves in itertools.groupby(c.execute('''
                SELECT (
                        SELECT username
                        FROM Users u
                        WHERE u.id = g.userid
                    ), tstamp - 60*60*5, level + 1
                FROM Guesses g
                WHERE solved
                ORDER BY (
                        SELECT u.level
                        FROM Users u
                        WHERE u.id = g.userid
                    ) DESC, (
                        SELECT MAX(g2.tstamp)
                        FROM Guesses g2
                        WHERE g2.userid = g.userid AND g2.solved
                    ) ASC
                ''').fetchall(), lambda x: x[0]):
            solves = list(solves)
            f.write('"{}"\n'.format(username))
            f.write('\n'.join('{} {}'.format(*x[1:]) for x in solves))
            f.write('\n{} {}\n\n\n'.format(now, solves[-1][2]))
    subprocess.run(['gnuplot', 'gnuplot'])
    static['/graph.png'] = (open('static/graph.png', 'rb').read(),
            mimetypes.guess_type('static/graph.png')[0])

class Handler(server.BaseHTTPRequestHandler):

    def __init__(self, *args):
        self.conn = sqlite3.connect('users.db')
        self.c = self.conn.cursor()
        server.BaseHTTPRequestHandler.__init__(self, *args)

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
        resp_code = None

        if re.fullmatch(r'/u\d+', self.path):
            puid = int(self.path[2:])
            pusername = self.c.execute('''
                    SELECT username
                    FROM Users
                    WHERE id = ?''', (puid,)).fetchone()
            if pusername:
                main_html = user_html(self.c, puid, pusername[0])
        elif re.fullmatch(r'/v\d+', self.path):
            if uid == 1:
                pid = int(self.path[2:])
                main_html = \
                        ('<a href="/v{}">« prev</a> | '
                         '<a href="/v{}">next »</a>').format(pid-1, pid+1) + \
                        htmldata['level' + self.path[2:]]
            else:
                resp_code = 403
                main_html = htmldata['403']
        elif self.path == '/users':
            main_html = userlist_html(self.c)
        elif self.path == '/messages' and uid:
            main_html = messages_html(self.c, uid, username)
        elif self.path == '/guesses' and uid == 1:
            main_html = viewguess_html(self.c)
        elif self.path == '/regraph' and uid == 1:
            main_html = 'graph regenerated'
            regraph(self.c)
        elif re.fullmatch(r'/r[A-Za-z0-9_-]*=*', self.path):
            try:
                txt = base64.urlsafe_b64decode(self.path[2:].encode()).decode()
                main_html = '<p>{}</p><p><a href="/">back</a></p>' \
                        .format(html.escape(txt))
            except (base64.binascii.Error, UnicodeDecodeError):
                pass
        elif self.path in ['/info', '/db', '/msg']:
            main_html = htmldata[self.path[1:]]
        elif self.path == '/':
            if level:
                main_html = htmldata['level' + str(level)] \
                        + guesses_html(self.c, uid, level)
            else:
                main_html = htmldata['login']

        resp_code = resp_code or (200 if main_html else 404)

        data = htmldata['base'] \
                .replace('[[messages]]', msgheader_html(self.c, uid)) \
                .replace('[[userinfo]]', userinfo_html(uid, username)) \
                .replace('[[main]]', main_html or htmldata['404']) \
                .replace('[[path]]', self.path) \
                .replace('[[username]]', str(username))

        if self.path == '/msg':
            data = data.replace('[[sendmsgrecip]]', '\n'.join(
                '<option value="{}">{}</option>'.format(user[0], user[1])
                for user in self.c.execute('SELECT id, username FROM Users')
            ))

        if '[[msg' in data:
            udata = self.c.execute('''
                    SELECT data
                    FROM UserData
                    WHERE userid = ? AND level = ?''',
                    (uid, level)).fetchone()
            udata = pickle.loads(udata[0]) if udata else None
            data = re.sub(r'\[\[msg(\d+)\]\]', lambda x:
                    getattr(check, 'msg' + x.group(1))(udata),
                    data)

        data = data.encode()

        self.send_response(resp_code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(data))
        if str(cookie):
            self.flush_headers()
            self.wfile.write(cookie.output().encode() + b'\r\n')
        self.end_headers()

        self.wfile.write(data)

        self.conn.commit()
        self.conn.close()

    def do_POST(self):
        resp = None
        redir = None

        # e[x]isting information
        (cookie, xuid, xusername, xlevel) = self.uinfo()

        qs = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        qs = urllib.parse.parse_qs(qs.decode())
        loginid = None

        if 'login' in qs and 'username' in qs and 'password' in qs:
            loginid = self.login(qs['username'][0], qs['password'][0])
        elif 'register' in qs and 'key' in qs and 'rpassword' in qs:
            loginid = self.register(qs['key'][0], qs['rpassword'][0])
        elif 'dbquery' in qs:
            if xuid == 1:
                resp = repr(self.c.execute(qs['dbquery'][0]).fetchall())
            else:
                resp = 'only Andy can do that'
        elif 'recipient' in qs and 'sendmsg' in qs:
            if xuid == 1:
                self.msg(int(qs['recipient'][0]), qs['sendmsg'][0])
                resp = 'sent'
            else:
                resp = 'only Andy can do that'
        elif 'markread' in qs and xuid:
            redir = '/messages'
            self.c.execute('''
                    UPDATE Messages
                    SET read = 1
                    WHERE userid = ?''', (xuid,))
        elif xlevel:
            ans_param = 'answer' + str(xlevel)
            cmd_param = 'cmd' + str(xlevel)
            if ans_param in qs:
                resp = self.guess(xuid, xlevel, qs[ans_param][0])
            elif cmd_param in qs:
                data = self.c.execute('''
                        SELECT data
                        FROM UserData
                        WHERE userid = ? AND level = ?''',
                        (xuid, xlevel)).fetchone()
                data = pickle.loads(data[0]) if data else None
                newdata = getattr(check, cmd_param)(data, qs[cmd_param][0])
                if newdata is True:
                    self.guess(xuid, xlevel, '')
                else:
                    newdata = pickle.dumps(newdata)
                    self.c.execute('''
                            UPDATE UserData
                            SET data = ?
                            WHERE userid = ? AND level = ?''',
                            (newdata, xuid, xlevel))
                    self.c.execute('''
                            INSERT INTO UserData (userid, level, data)
                            SELECT ?, ?, ?
                            WHERE (SELECT changes() = 0)''',
                            (xuid, xlevel, newdata))

        sid = None
        if loginid:
            sid = uuid.uuid4().hex
            self.c.execute('''
                    INSERT INTO Sessions (userid, cookie)
                    VALUES (?, ?)''', (loginid, sid))

        self.send_response(302)

        if sid: self.send_header('Set-Cookie', 'session={}'.format(sid))

        if resp: self.send_header('Location', '/r' +
                base64.urlsafe_b64encode(resp.encode()).decode())
        elif redir: self.send_header('Location', redir)
        else: self.send_header('Location', '/')

        self.end_headers()

        self.conn.commit()
        self.conn.close()

    def uinfo(self):
        uid, username, level = None, None, None
        cookie = cookies.SimpleCookie()
        if self.headers.get('Cookie'):
            cookie.load(self.headers.get('Cookie'))
            if 'session' in cookie:
                vals = self.c.execute('''
                        SELECT u.id, u.username, u.level
                        FROM Users u
                        LEFT JOIN Sessions
                        WHERE u.id = userid AND cookie = ?
                        ''', (cookie['session'].value,)).fetchone()
                if vals:
                    uid, username, level = vals
        return (cookie, uid, username, level)

    def login(self, username, password):
        vals = self.c.execute('''
                SELECT id, salt, hash
                FROM Users
                WHERE username = ?
                COLLATE NOCASE''', (username,)).fetchone()
        if vals:
            uid, salt, hsh = vals
            if hsh == hashlib.sha512((salt + password).encode()).hexdigest():
                return uid

    def register(self, key, password):
        username = self.c.execute('SELECT username FROM Keys WHERE key = ?',
                (key,)).fetchone()
        if username and len(password) > 0:
            username = username[0]
            salt = uuid.uuid4().hex
            hsh = hashlib.sha512((salt + password).encode()).hexdigest()
            self.c.execute('DELETE FROM Keys WHERE key = ?', (key,))
            self.c.execute('''
                    INSERT INTO Users (username, hash, salt, level)
                    VALUES (?, ?, ?, 1)
                    ''', (username, hsh, salt))
            return self.c.execute('SELECT last_insert_rowid()').fetchone()[0]

    def guess(self, uid, level, txt):
        last_guess = self.c.execute('''
                SELECT tstamp
                FROM Guesses
                WHERE userid = ? AND level = ?
                ORDER BY tstamp DESC
                LIMIT 1
                ''', (uid, level)).fetchone()

        if last_guess and time.time() - last_guess[0] < 60:
            return 'you must wait at least a minute between guesses.'
        elif len(txt) > 500:
            return 'your guess is too long.'
        else:
            txt = txt.strip().replace('\r\n', '\n')
            solved = getattr(check, 'check' + str(level))(txt)
            self.c.execute('''
                    INSERT INTO Guesses (userid, level, guess, solved, tstamp)
                    VALUES (?, ?, ?, ?, ?)
                    ''',
                    (uid, level, txt, 1 if solved else 0, int(time.time())))
            if solved:
                self.c.execute('UPDATE Users SET level = ? WHERE id = ?',
                        (level + 1, uid))

    def msg(self, recipient, msg):
        if recipient == 0:
            maxid = self.c.execute('SELECT MAX(id) FROM USERS').fetchone()[0]
            for i in range(maxid): self.msg(i+1, msg)
        else:
            self.c.execute('''
                    INSERT INTO Messages (userid, message, read, tstamp)
                    VALUES (?, ?, 0, ?)
                    ''', (recipient, msg, int(time.time())))

    def log_message(self, fmt, *args):
        msg = "{} - - [{}] {}\n".format(
                self.client_address[0],
                self.log_date_time_string(),
                fmt % args)
        log_file.write(msg.encode())
        log_file.flush()
        sys.stderr.write(msg)
        sys.stderr.flush()

class Server(socketserver.ThreadingMixIn, server.HTTPServer):
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
