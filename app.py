import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import pytz
import re

from helpers import apology, login_required, lookup, usd

# API token key pk_b26444b73e1d4d0fa82001b808c7feae

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # checks if a transactions table exists
    number = db.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='transactions' ''')
    if number[0]['count(name)'] == 0:
        db.execute('CREATE TABLE transactions (transaction_id INTEGER PRIMARY KEY, user_id INTEGER, ticker TEXT NOT NULL, price INTEGER, shares INTEGER, type TEXT NOT NULL, date TEXT NOT NULL, time_pst TEXT NOT NULL)')

    # get user id
    userId = int(session.get('user_id'))
    # search for all of the user's transactions
    dataQuery = 'SELECT transactions.ticker, transactions.shares, transactions.type FROM transactions WHERE transactions.user_id = ?'
    data = db.execute(dataQuery, (userId,))

    # queries for the user's current cash amount
    currentCashQuery = 'SELECT users.cash FROM users WHERE users.id = ?'
    currentCash = db.execute(currentCashQuery, (userId,))
    currentCash = currentCash[0]['cash']
    totalValue = currentCash

    # gets list of all the unique tickers
    unique = []
    tickers = []
    for i in range(len(data)):
        if data[i]['ticker'] not in unique:
            unique.append(data[i]['ticker'])

    stocks = []
    # loop through the unique tickers
    for i in range(len(unique)):
        # create a dict to store information about a singular user-owned stock
        stock = {}

        # queries for the sum of the shares that the user has ever bought
        buyQuery = 'SELECT SUM(transactions.shares) FROM transactions WHERE transactions.ticker = ? AND transactions.type = ? AND transactions.user_id = ?'
        buySum = db.execute(buyQuery, (unique[i],), ('Buy',), (userId,))

        # queries for the sum of the shares that the user has ever sold
        sellQuery = 'SELECT SUM(transactions.shares) FROM transactions WHERE transactions.ticker = ? AND transactions.type = ? AND transactions.user_id = ?'
        sellSum = db.execute(sellQuery, (unique[i],), ('Sell',), (userId,))

        # checks for edge case if user has None shares
        if sellSum[0]['SUM(transactions.shares)'] == None:
            sellSum[0]['SUM(transactions.shares)'] = 0

        shares = buySum[0]['SUM(transactions.shares)'] - sellSum[0]['SUM(transactions.shares)']
        # checks if user has existing shares
        if shares > 0:
            # find the current quote for the i'th ticker
            currentQuote = lookup(unique[i])
            currentPrice = currentQuote['price']
            stock['ticker'] = unique[i]
            stock['price'] = usd(currentPrice)
            stock['shares'] = shares
            stock['value'] = usd(shares * currentPrice)
            totalValue += shares * currentPrice

            # append the stock to the stocks list
            stocks.append(stock)

    return render_template('index.html', stocks=stocks, cash=currentCash, total=totalValue)


@app.route('/changePassword', methods=['GET', 'POST'])
@login_required
def changePassword():
    '''Change User Password'''
    # tracks if password has been changed
    changed = False

    if request.method == 'POST':
        # obtain user id, and form data
        userID = int(session.get('user_id'))
        oldPassword = request.form.get('oldPassword')
        newPassword = request.form.get('newPassword')
        confirm = request.form.get('confirmation')
        oldPassQuery = 'SELECT users.hash FROM users WHERE users.id = ?'
        oldPass = db.execute(oldPassQuery, (userID,))

        # checks if old password is entered correctly
        if not check_password_hash(oldPass[0]['hash'], oldPassword):
            return apology('Incorrect Password')

        # checks if new password is typed correctly
        if newPassword != confirm:
            return apology('Passwords do not match!')

        # checks if password is of a set structure
        if not validate(newPassword):
            return apology('Password must be at least 8 letters and contain at least 1 capital letter, 1 digit, and 1 special character!')

        # update the user's password
        updatePassQuery = 'UPDATE users SET hash = ? WHERE id = ?'
        db.execute(updatePassQuery, (generate_password_hash(newPassword)), (userID,))
        changed = True

        return render_template('changePassword.html', changed=changed)
    else:
        return render_template('changePassword.html', changed=changed)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        # look up information for desired quote
        ticker = request.form.get('symbol')
        ticker = ticker.upper()
        shares = request.form.get('shares')
        data = lookup(ticker)

        # if ticker does not exist
        if data == None:
            return apology('Ticker not found!')

        # if desired shares is not numeric
        if not shares.isnumeric():
            return apology('Please enter a positive number of shares!')

        # if the desired shares is fractional
        if float(shares) % 1 != 0:
            return apology('Please enter a whole number of shares!')

        # obtain user id and current user cash balance
        userId = int(session.get('user_id'))
        cashQuery = 'SELECT users.cash FROM users WHERE users.id = ?'
        cashVal = db.execute(cashQuery, (userId,))
        cash = cashVal[0]['cash']

        # total cost of desired purchase
        totalCost = data['price'] * int(shares)

        # if user does not have enough cash
        if cash < totalCost:
            return apology('Not enough cash!')

        # finds local time and date in PST
        tzPST = pytz.timezone('US/Pacific')
        datetimePST = datetime.now(tzPST)
        time = datetimePST.strftime("%H:%M:%S")
        date = str(datetime.now(tzPST))
        date = date[0:10]

        # insert transaction
        db.execute('INSERT INTO transactions (user_id, ticker, price, shares, type, date, time_pst) VALUES(?, ?, ?, ?, ?, ?, ?)',
                   userId, ticker, usd(data['price']), int(shares), 'Buy', date, time)

        # update user cash balance
        cashLeft = cash - totalCost
        cashUpdateQuery = 'UPDATE users SET cash = ? WHERE id = ?'
        db.execute(cashUpdateQuery, (cashLeft,), (userId,))

        return render_template('quoted.html', sym=ticker, shares=shares, price=data['price'], total=totalCost, cash=cashLeft)
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    userID = int(session.get('user_id'))
    # query for the list of the user's transaction history
    transactionsQuery = 'SELECT * FROM transactions WHERE transactions.user_id = ?'
    transactions = db.execute(transactionsQuery, (userID))

    return render_template('history.html', transactions=transactions)


@app.route('/addCash', methods=['GET', 'POST'])
@login_required
def addCash():
    '''Allow user to add cash to current balance'''
    # checks if user added any cash
    changed = False

    # obtain user id and current cash balance
    userID = int(session.get('user_id'))
    currentCashQuery = 'SELECT users.cash FROM users WHERE users.id = ?'
    currentCash = db.execute(currentCashQuery, (userID,))
    currentCash = currentCash[0]['cash']

    if request.method == 'POST':
        # obtain desired amount of cash to add
        cashAmount = request.form.get('amount')
        cashAmount = int(cashAmount)
        newTotal = currentCash + cashAmount

        # update user's new cash balance
        updateCashQuery = 'UPDATE users SET cash = ? WHERE id = ?'
        db.execute(updateCashQuery, (newTotal,), (userID,))

        return render_template('addCash.html', changed=changed, cash=newTotal)
    else:
        return render_template('addCash.html', changed=changed, cash=currentCash)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':

        # look up data of desired ticker
        ticker = request.form.get('symbol')
        data = lookup(ticker)

        if data == None:
            return apology("Ticker not found!")

        return render_template('quoted.html', name=data['name'], price=data['price'], sym=data['symbol'])
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        # obtains form data
        user = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirmation')
        users = db.execute('SELECT users.username FROM users')

        # for each user, check if the desired username has been taken
        for i in range(len(users)):
            if users[i]['username'] == user:
                return apology('Username already taken')

        # checks if the passwords match
        if password != confirm:
            return apology('Passwords do not match!')

        # checks if the password follows a certain structure
        if not validate(password):
            return apology('Password must be at least 8 letters and contain at least 1 capital letter, 1 digit, and 1 special character!')

        # insert new user into the database
        db.execute('INSERT INTO users (username, hash) VALUES(?, ?)', user, generate_password_hash(password))
        return render_template('login.html')
    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # obtain user id
    userId = int(session.get('user_id'))

    # query for all of the user's transactions
    dataQuery = 'SELECT transactions.ticker, transactions.shares, transactions.type FROM transactions WHERE transactions.user_id = ?'
    data = db.execute(dataQuery, (userId,))

    if request.method == 'POST':
        option = request.form.get('symbol')

        # checks if user has selected a ticker
        if option == None:
            return apology('Select a ticker!')

        # look up data for the desired ticker
        currentQuote = lookup(option)
        currentPrice = currentQuote['price']
        shares = request.form.get('shares')

        # checks if desired shares is a whole number
        if float(shares) % 1 != 0:
            return apology('Please enter a whole number of shares!')

        # checks if desired shares is a number
        if not shares.isnumeric():
            return apology('Please enter a positive number of shares!')

        # queries for the user's current cash amount
        currentCashQuery = 'SELECT users.cash FROM users WHERE users.id = ?'
        currentCash = db.execute(currentCashQuery, (userId,))
        currentCash = currentCash[0]['cash']
        cashLeft = currentCash

        # create a dict to store information about a singular user-owned stock
        stock = {}
        # queries for the sum of the shares that the user has ever bought
        buyQuery = 'SELECT SUM(transactions.shares) FROM transactions WHERE transactions.ticker = ? AND transactions.type = ? AND transactions.user_id = ?'
        buySum = db.execute(buyQuery, (option,), ('Buy',), (userId,))
        print(buySum)
        # queries for the sum of the shares that the user has ever sold
        sellQuery = 'SELECT SUM(transactions.shares) FROM transactions WHERE transactions.ticker = ? AND transactions.type = ? AND transactions.user_id = ?'
        sellSum = db.execute(sellQuery, (option,), ('Sell',), (userId,))
        print(sellSum)

        # checks for edge case if user has None shares
        if sellSum[0]['SUM(transactions.shares)'] == None:
            sellSum[0]['SUM(transactions.shares)'] = 0

        # checks if user has existing shares
        existingShares = buySum[0]['SUM(transactions.shares)'] - sellSum[0]['SUM(transactions.shares)']

        # if the desired shares is less than or equal the existing shares, allow the transaction
        if int(shares) <= existingShares:
            currentQuote = lookup(option)
            currentPrice = currentQuote['price']
            stock['ticker'] = option
            stock['price'] = usd(currentPrice)
            stock['shares'] = int(shares)
            stock['value'] = usd(int(shares) * currentPrice)
            cashLeft = currentCash + (int(shares) * currentPrice)
        else:
            return apology('You do not own enough shares!')

        # record date and time of transaction
        tzPST = pytz.timezone('US/Pacific')
        datetimePST = datetime.now(tzPST)
        time = datetimePST.strftime("%H:%M:%S")
        date = str(datetime.now(tzPST))
        date = date[0:10]

        db.execute('INSERT INTO transactions (user_id, ticker, price, shares, type, date, time_pst) VALUES(?, ?, ?, ?, ?, ?, ?)',
                   userId, option, stock['price'], int(shares), 'Sell', date, time)

        # queries to update the user's cash
        cashUpdateQuery = 'UPDATE users SET cash = ? WHERE id = ?'
        cashUpdate = db.execute(cashUpdateQuery, (cashLeft,), (userId,))

        return render_template('sold.html', stock=stock, cash=cashLeft)
    else:
        # selects all the unique tickers a user owns
        tickers = []

        # loop through the user's portfolio to look for unique tickers
        for i in range(len(data)):
            if data[i]['ticker'] not in tickers:
                tickers.append(data[i]['ticker'])

        # render all of them on a html page
        return render_template('sell.html', tickers=tickers)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# checks that a password is valid


def validate(password):
    # special chars
    pattern = '[!@#$%^&*()-+?_=,<>/]'

    # checks if password length is greater than 8 and contains at least 1 capital letter, 1 digit, and 1 special char
    if len(password) < 8:
        return False
    if re.search('[0-9]', password) is None:
        return False
    if re.search('[A-Z]', password) is None:
        return False
    if re.search(pattern, password) is None:
        return False

    return True


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
