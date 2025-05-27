from flask import Flask , render_template,redirect,url_for,request,flash
from flask_login import login_user,logout_user,login_required,current_user,LoginManager
from models import db ,User
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from flask import abort
from routes import register_routes

app=Flask(__name__)

app.config['SECRET_KEY']="sarthak"
app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///db.sqlite3'

db.init_app(app)

login_manager=LoginManager()
login_manager.login_view='auth.login'
login_manager.init_app(app)

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args,**kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args,**kwargs)
        return wrapped
    return decorator    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/get-started')
def get_started():
    return render_template('get_started.html')


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form['username']
        password=generate_password_hash(request.form['password'])
        role=request.form['role']

        user=User(username=username,password=password,role=role)
        db.session.add(user)
        db.session.commit()

        flash('registered successfully .PLease login')
        return redirect(url_for('login'))
    
    return render_template('register.html')


# @app.route('/login',methods=['GET','POST'])
# def login():
#     if request.method=="POST":
#         user=User.query.filter_by(username=request.form['username']).first()
#         if user and check_password_hash(user.password,request.form['password']):
#             login_user(user)
#             return redirect(url_for('dashboard'))
#         else:
#             flash("invalid credentials")
#     return render_template('login.html')        

# @app.route('/logout',methods=["GET",'POST'])
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            
            # Redirect based on user role
            role = user.role.lower()
            if role == 'admin':
                return redirect(url_for('admin_page'))
            elif role == 'sales':
                return redirect(url_for('sales_page'))
            elif role == 'warehouse':
                return redirect(url_for('warehouse_page'))
            elif role == 'production':
                return redirect(url_for('production_page'))
            elif role == 'support':
                return redirect(url_for('support_page'))
            else:
                return redirect(url_for('dashboard'))  # fallback

        else:
            flash("Invalid credentials")

    return render_template('login.html')

    


    
@app.route('/dashboard')
@login_required #middleware of security 
def dashboard():
    return render_template('dashboard.html',user=current_user)

@app.route('/admin')
@login_required
@role_required('admin')
def admin_page():
    return render_template('admin.html')

@app.route('/sales')
@login_required
@role_required('admin', 'sales')
def sales_page():
    return render_template('sales.html')

@app.route('/warehouse')
@login_required
@role_required('admin', 'warehouse')
def warehouse_page():
     return render_template('warehouse.html')

@app.route('/production')
@login_required
@role_required('admin', 'production')
def production_page():
    return render_template('production.html')

@app.route('/support')
@login_required
@role_required('admin', 'support')
def support_page():
   return render_template('support.html')


if __name__=='__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)    
