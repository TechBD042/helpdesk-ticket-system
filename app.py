"""
HelpDesk Pro - IT Support Ticketing System
A complete help desk solution for learning and portfolio demonstration.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    department = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    tickets_created = db.relationship('Ticket', backref='requester', lazy=True, foreign_keys='Ticket.requester_id')
    tickets_assigned = db.relationship('Ticket', backref='assignee', lazy=True, foreign_keys='Ticket.assignee_id')

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General')
    priority = db.Column(db.String(20), default='Medium')
    status = db.Column(db.String(20), default='Open')
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    contact_method = db.Column(db.String(50))
    location = db.Column(db.String(100))
    asset_tag = db.Column(db.String(50))
    
    comments = db.relationship('TicketComment', backref='ticket', lazy=True, order_by='TicketComment.created_at')

    @staticmethod
    def generate_ticket_number():
        today = datetime.utcnow().strftime('%Y%m%d')
        count = Ticket.query.filter(Ticket.ticket_number.like(f'TKT-{today}%')).count()
        return f'TKT-{today}-{str(count + 1).zfill(3)}'


class TicketComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_internal = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='comments')


class KnowledgeBase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    tags = db.Column(db.String(200))
    views = db.Column(db.Integer, default=0)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    author = db.relationship('User', backref='articles')


# =============================================================================
# AUTHENTICATION HELPERS
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def tech_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role not in ['technician', 'admin']:
            flash('Access denied. Technician privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        department = request.form.get('department')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        user = User(username=username, email=email, department=department)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# =============================================================================
# ROUTES - DASHBOARD
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    user = get_current_user()
    
    if user.role in ['technician', 'admin']:
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status='Open').count()
        in_progress = Ticket.query.filter_by(status='In Progress').count()
        pending = Ticket.query.filter_by(status='Pending').count()
        resolved_today = Ticket.query.filter(
            Ticket.resolved_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
        ).count()
        
        my_tickets = Ticket.query.filter_by(assignee_id=user.id).filter(
            Ticket.status.in_(['Open', 'In Progress', 'Pending'])
        ).order_by(Ticket.created_at.desc()).limit(10).all()
        
        unassigned = Ticket.query.filter_by(assignee_id=None, status='Open').order_by(
            Ticket.created_at.desc()
        ).limit(10).all()
        
        critical_tickets = Ticket.query.filter_by(priority='Critical').filter(
            Ticket.status.in_(['Open', 'In Progress'])
        ).all()
    else:
        total_tickets = Ticket.query.filter_by(requester_id=user.id).count()
        open_tickets = Ticket.query.filter_by(requester_id=user.id, status='Open').count()
        in_progress = Ticket.query.filter_by(requester_id=user.id, status='In Progress').count()
        pending = Ticket.query.filter_by(requester_id=user.id, status='Pending').count()
        resolved_today = 0
        my_tickets = Ticket.query.filter_by(requester_id=user.id).filter(
            Ticket.status.in_(['Open', 'In Progress', 'Pending'])
        ).order_by(Ticket.created_at.desc()).limit(10).all()
        unassigned = []
        critical_tickets = []
    
    recent_tickets = Ticket.query.order_by(Ticket.updated_at.desc()).limit(5).all()
    
    # Get counts by status
    resolved = Ticket.query.filter_by(status='Resolved').count()
    closed = Ticket.query.filter_by(status='Closed').count()
    
    # Get counts by priority  
    critical = Ticket.query.filter_by(priority='Critical').count()
    high = Ticket.query.filter_by(priority='High').count()
    medium = Ticket.query.filter_by(priority='Medium').count()
    low = Ticket.query.filter_by(priority='Low').count()
    
    stats = {
        'total': total_tickets,
        'open': open_tickets,
        'in_progress': in_progress,
        'pending': pending,
        'resolved_today': resolved_today,
        'resolved': resolved,
        'closed': closed,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low
    }
    
    return render_template('dashboard.html', 
                         user=user, 
                         stats=stats, 
                         my_tickets=my_tickets,
                         unassigned=unassigned,
                         critical_tickets=critical_tickets,
                         recent_tickets=recent_tickets)


# =============================================================================
# ROUTES - TICKETS
# =============================================================================

@app.route('/tickets')
@login_required
def ticket_list():
    user = get_current_user()
    
    status = request.args.get('status', '')
    priority = request.args.get('priority', '')
    category = request.args.get('category', '')
    assignee = request.args.get('assignee', '')
    search = request.args.get('search', '')
    
    query = Ticket.query
    
    if user.role == 'user':
        query = query.filter_by(requester_id=user.id)
    
    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)
    if category:
        query = query.filter_by(category=category)
    if assignee:
        if assignee == 'unassigned':
            query = query.filter_by(assignee_id=None)
        elif assignee == 'me':
            query = query.filter_by(assignee_id=user.id)
        else:
            query = query.filter_by(assignee_id=int(assignee))
    if search:
        query = query.filter(
            (Ticket.subject.ilike(f'%{search}%')) | 
            (Ticket.ticket_number.ilike(f'%{search}%')) |
            (Ticket.description.ilike(f'%{search}%'))
        )
    
    tickets = query.order_by(Ticket.created_at.desc()).all()
    technicians = User.query.filter(User.role.in_(['technician', 'admin'])).all()
    
    return render_template('tickets.html', 
                         tickets=tickets, 
                         technicians=technicians,
                         user=user,
                         filters={'status': status, 'priority': priority, 'category': category, 'assignee': assignee, 'search': search})


@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def create_ticket():
    user = get_current_user()
    
    if request.method == 'POST':
        ticket = Ticket(
            ticket_number=Ticket.generate_ticket_number(),
            subject=request.form.get('subject'),
            description=request.form.get('description'),
            category=request.form.get('category'),
            priority=request.form.get('priority', 'Medium'),
            requester_id=user.id,
            contact_method=request.form.get('contact_method'),
            location=request.form.get('location'),
            asset_tag=request.form.get('asset_tag')
        )
        
        priority_hours = {'Critical': 4, 'High': 8, 'Medium': 24, 'Low': 48}
        ticket.due_date = datetime.utcnow() + timedelta(hours=priority_hours.get(ticket.priority, 24))
        
        db.session.add(ticket)
        db.session.commit()
        
        flash(f'Ticket {ticket.ticket_number} created successfully!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))
    
    categories = ['Hardware', 'Software', 'Network', 'Email', 'Account Access', 'Printer', 'VPN', 'Other']
    return render_template('create_ticket.html', categories=categories, user=user)


@app.route('/tickets/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    user = get_current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if user.role == 'user' and ticket.requester_id != user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('ticket_list'))
    
    technicians = User.query.filter(User.role.in_(['technician', 'admin'])).all()
    return render_template('view_ticket.html', ticket=ticket, technicians=technicians, user=user)


@app.route('/tickets/<int:ticket_id>/update', methods=['POST'])
@login_required
def update_ticket(ticket_id):
    user = get_current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if 'status' in request.form:
        old_status = ticket.status
        ticket.status = request.form.get('status')
        if ticket.status == 'Resolved' and old_status != 'Resolved':
            ticket.resolved_at = datetime.utcnow()
    
    if 'priority' in request.form:
        ticket.priority = request.form.get('priority')
    
    if 'assignee_id' in request.form:
        assignee_id = request.form.get('assignee_id')
        ticket.assignee_id = int(assignee_id) if assignee_id else None
        if ticket.assignee_id and ticket.status == 'Open':
            ticket.status = 'In Progress'
    
    if 'category' in request.form:
        ticket.category = request.form.get('category')
    
    db.session.commit()
    flash('Ticket updated successfully.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/tickets/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    user = get_current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    
    content = request.form.get('content')
    is_internal = request.form.get('is_internal') == 'on'
    
    if content:
        comment = TicketComment(
            ticket_id=ticket_id,
            user_id=user.id,
            content=content,
            is_internal=is_internal
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added.', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


# =============================================================================
# ROUTES - KNOWLEDGE BASE
# =============================================================================

@app.route('/knowledge')
@login_required
def knowledge_base():
    user = get_current_user()
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    query = KnowledgeBase.query
    
    if search:
        query = query.filter(
            (KnowledgeBase.title.ilike(f'%{search}%')) |
            (KnowledgeBase.content.ilike(f'%{search}%')) |
            (KnowledgeBase.tags.ilike(f'%{search}%'))
        )
    if category:
        query = query.filter_by(category=category)
    
    articles = query.order_by(KnowledgeBase.views.desc()).all()
    categories = db.session.query(KnowledgeBase.category).distinct().all()
    
    return render_template('knowledge_base.html', articles=articles, categories=categories, user=user)


@app.route('/knowledge/<int:article_id>')
@login_required
def view_article(article_id):
    user = get_current_user()
    article = KnowledgeBase.query.get_or_404(article_id)
    article.views += 1
    db.session.commit()
    return render_template('view_article.html', article=article, user=user)


@app.route('/knowledge/new', methods=['GET', 'POST'])
@tech_required
def create_article():
    user = get_current_user()
    
    if request.method == 'POST':
        article = KnowledgeBase(
            title=request.form.get('title'),
            content=request.form.get('content'),
            category=request.form.get('category'),
            tags=request.form.get('tags'),
            created_by=user.id
        )
        db.session.add(article)
        db.session.commit()
        flash('Article created successfully!', 'success')
        return redirect(url_for('view_article', article_id=article.id))
    
    return render_template('create_article.html', user=user)


# =============================================================================
# ROUTES - REPORTS
# =============================================================================

@app.route('/reports')
@tech_required
def reports():
    user = get_current_user()
    
    total = Ticket.query.count()
    by_status = db.session.query(Ticket.status, db.func.count(Ticket.id)).group_by(Ticket.status).all()
    by_priority = db.session.query(Ticket.priority, db.func.count(Ticket.id)).group_by(Ticket.priority).all()
    by_category = db.session.query(Ticket.category, db.func.count(Ticket.id)).group_by(Ticket.category).all()
    
    week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_created = Ticket.query.filter(Ticket.created_at >= week_ago).count()
    weekly_resolved = Ticket.query.filter(Ticket.resolved_at >= week_ago).count()
    
    tech_stats = db.session.query(
        User.username,
        db.func.count(Ticket.id).label('assigned'),
        db.func.sum(db.case((Ticket.status == 'Resolved', 1), else_=0)).label('resolved')
    ).join(Ticket, User.id == Ticket.assignee_id).filter(
        User.role.in_(['technician', 'admin'])
    ).group_by(User.id).all()
    
    return render_template('reports.html', 
                         user=user,
                         total=total,
                         by_status=dict(by_status),
                         by_priority=dict(by_priority),
                         by_category=dict(by_category),
                         weekly_created=weekly_created,
                         weekly_resolved=weekly_resolved,
                         tech_stats=tech_stats)


@app.route('/api/stats')
@login_required
def api_stats():
    by_status = db.session.query(Ticket.status, db.func.count(Ticket.id)).group_by(Ticket.status).all()
    by_priority = db.session.query(Ticket.priority, db.func.count(Ticket.id)).group_by(Ticket.priority).all()
    
    return jsonify({
        'by_status': dict(by_status),
        'by_priority': dict(by_priority)
    })


# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def init_db():
    db.create_all()
    
    if User.query.first():
        return
    
    admin = User(username='DGSource', email='Demarib2000@yahoo.com', role='admin', department='IT')
    admin.set_password('Helpdesk2024!')
    db.session.add(admin)
    
    tech = User(username='tech1', email='tech1@helpdesk.local', role='technician', department='IT Support')
    tech.set_password('tech123')
    db.session.add(tech)
    
    user = User(username='jsmith', email='jsmith@company.local', role='user', department='Marketing')
    user.set_password('user123')
    db.session.add(user)
    
    db.session.commit()
    
    sample_tickets = [
        {'subject': 'Cannot connect to VPN', 'description': 'Getting authentication error when connecting from home.', 'category': 'VPN', 'priority': 'High', 'requester_id': user.id},
        {'subject': 'Outlook keeps crashing', 'description': 'Crashes when opening attachments after Windows update.', 'category': 'Software', 'priority': 'Medium', 'requester_id': user.id},
        {'subject': 'Need password reset for ERP', 'description': 'Forgot password, need reset.', 'category': 'Account Access', 'priority': 'Medium', 'requester_id': user.id, 'assignee_id': tech.id, 'status': 'In Progress'},
        {'subject': 'Printer offline - Building A', 'description': 'Main printer showing offline, multiple users affected.', 'category': 'Printer', 'priority': 'High', 'requester_id': user.id},
        {'subject': 'New laptop setup', 'description': 'New employee starting Monday needs laptop configured.', 'category': 'Hardware', 'priority': 'Low', 'requester_id': user.id, 'assignee_id': tech.id, 'status': 'Pending'}
    ]
    
    for t_data in sample_tickets:
        ticket = Ticket(ticket_number=Ticket.generate_ticket_number(), **t_data)
        priority_hours = {'Critical': 4, 'High': 8, 'Medium': 24, 'Low': 48}
        ticket.due_date = datetime.utcnow() + timedelta(hours=priority_hours.get(ticket.priority, 24))
        db.session.add(ticket)
    
    db.session.commit()
    
    kb_articles = [
        {'title': 'How to Reset Your Password', 'content': '## Password Reset\n\n1. Go to password.company.local\n2. Click Forgot Password\n3. Enter username and email\n4. Check email for reset link', 'category': 'Account Access', 'tags': 'password, reset, login', 'created_by': admin.id},
        {'title': 'VPN Troubleshooting', 'content': '## VPN Issues\n\n**Auth Failed:** Verify credentials, check MFA\n**Timeout:** Try different network, restart client', 'category': 'Network', 'tags': 'vpn, remote, connection', 'created_by': admin.id},
        {'title': 'Printer Setup Guide', 'content': '## Adding Printer\n\n1. Settings > Devices > Printers\n2. Add printer\n3. Enter IP address', 'category': 'Hardware', 'tags': 'printer, setup', 'created_by': tech.id}
    ]
    
    for article_data in kb_articles:
        article = KnowledgeBase(**article_data)
        db.session.add(article)
    
    db.session.commit()
    print("Database initialized with sample data!")


@app.context_processor
def utility_processor():
    return {'now': datetime.utcnow(), 'current_user': get_current_user}


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)

# Force reset on next deploy
import os
if os.environ.get('RENDER'):
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(username='DGSource', email='Demarib2000@yahoo.com', role='admin', department='IT')
        admin.set_password('Helpdesk2024!')
        db.session.add(admin)
        db.session.commit()
        print("Database reset with new admin!")


# =============================================================================
# AI SUGGESTED RESPONSES
# =============================================================================

@app.route('/api/suggest-response', methods=['POST'])
@login_required
def suggest_response():
    """Generate AI-suggested response for a ticket"""
    data = request.get_json()
    ticket_id = data.get('ticket_id')
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Build context from ticket
    context = f"""
    Ticket Subject: {ticket.subject}
    Category: {ticket.category}
    Priority: {ticket.priority}
    Description: {ticket.description}
    """
    
    # Add previous comments for context
    if ticket.comments:
        context += "\n\nPrevious comments:\n"
        for comment in ticket.comments[-3:]:  # Last 3 comments
            context += f"- {comment.user.username}: {comment.content[:200]}\n"
    
    # Generate suggested response based on category
    suggestions = {
        'Hardware': f"Hi {ticket.requester.username},\n\nThank you for reporting this hardware issue. I'll need to gather some additional information:\n\n1. When did this issue first occur?\n2. Have you tried restarting the device?\n3. Are there any error lights or messages?\n\nI'll schedule a time to come look at the equipment. What times work best for you today?\n\nBest regards,\nIT Support",
        
        'Software': f"Hi {ticket.requester.username},\n\nThank you for reaching out about this software issue. Let's try a few troubleshooting steps:\n\n1. Please close the application completely and reopen it\n2. If that doesn't work, try restarting your computer\n3. Make sure the software is up to date\n\nIf the issue persists after trying these steps, please let me know and I'll remote in to take a closer look.\n\nBest regards,\nIT Support",
        
        'Network': f"Hi {ticket.requester.username},\n\nI understand you're having network connectivity issues. Let's troubleshoot:\n\n1. Are other devices on the same network working?\n2. Have you tried disconnecting and reconnecting to the network?\n3. Can you try restarting your router/modem?\n\nIf you're in the office, I'll come check the physical connection. If remote, let's schedule a call.\n\nBest regards,\nIT Support",
        
        'VPN': f"Hi {ticket.requester.username},\n\nSorry to hear you're having VPN issues. This is often related to credentials or network settings. Please try:\n\n1. Completely close the VPN client\n2. Restart your computer\n3. Ensure you're using your current network password\n4. Try connecting from a different network if possible\n\nIf you recently changed your password, it may take up to an hour to sync. Let me know if issues persist.\n\nBest regards,\nIT Support",
        
        'Account Access': f"Hi {ticket.requester.username},\n\nI can help you with your account access issue. For security purposes, I'll need to verify your identity.\n\nPlease confirm:\n1. Your employee ID or department\n2. Your manager's name\n\nOnce verified, I'll reset your access immediately. For future reference, you can also use the self-service password reset at password.company.local.\n\nBest regards,\nIT Support",
        
        'Email': f"Hi {ticket.requester.username},\n\nThank you for reporting this email issue. Let's get this resolved:\n\n1. Are you accessing email via web (Outlook.com) or the desktop app?\n2. Have you tried logging out and back in?\n3. Is the issue affecting sending, receiving, or both?\n\nI'll check the server status on our end. In the meantime, you can access email via the web portal as a backup.\n\nBest regards,\nIT Support",
        
        'Printer': f"Hi {ticket.requester.username},\n\nI'll help you resolve this printer issue. Please try these steps:\n\n1. Check if the printer is powered on and showing ready\n2. Ensure paper is loaded and no jams are indicated\n3. Try removing and re-adding the printer in Settings > Devices > Printers\n\nIf the issue affects multiple users, I'll come check the printer directly. What's the printer location?\n\nBest regards,\nIT Support"
    }
    
    # Get suggestion based on category, with a default fallback
    suggested = suggestions.get(ticket.category, f"Hi {ticket.requester.username},\n\nThank you for submitting this ticket. I'm reviewing your request and will follow up shortly with next steps.\n\nCould you provide any additional details that might help me resolve this faster?\n\nBest regards,\nIT Support")
    
    return jsonify({'suggestion': suggested})


# =============================================================================
# FILE ATTACHMENTS
# =============================================================================

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'csv', 'xlsx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    ticket = db.relationship('Ticket', backref='attachments')
    uploader = db.relationship('User')


@app.route('/tickets/<int:ticket_id>/upload', methods=['POST'])
@login_required
def upload_file(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    user = get_current_user()
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        # Create unique filename
        unique_filename = f"{ticket_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        attachment = Attachment(
            ticket_id=ticket_id,
            filename=unique_filename,
            original_filename=original_filename,
            uploaded_by=user.id
        )
        db.session.add(attachment)
        db.session.commit()
        
        flash('File uploaded successfully!', 'success')
    else:
        flash('File type not allowed', 'danger')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Create attachment table
with app.app_context():
    db.create_all()
