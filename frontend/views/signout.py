from flask_login import login_required, logout_user, url_for
from flask import redirect, Blueprint
logout_bp = Blueprint('logout', __name__)


@logout_bp.route('/logout')
@login_required
def logout():
    """
    User logout form
    """
    logout_user()
    return redirect(url_for("login.main_login"))