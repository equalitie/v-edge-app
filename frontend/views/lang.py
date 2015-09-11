from flask import redirect, Blueprint, make_response
lang_bp = Blueprint('lang', __name__)


@lang_bp.route('/lang/<lang>')
def change_lang(lang):
    """
    Change the language for the user. If a new language is to be supported, add it to the list down here.
    """
    # check allowed languages
    allowed_langs = ["en", "fr", "ru"]

    if lang in allowed_langs:
        # all looks good, return to where we came from
        resp = make_response(redirect("/"))
        resp.set_cookie('lang', lang)

        return resp

    return redirect("/")