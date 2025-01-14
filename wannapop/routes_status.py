from flask import Blueprint, render_template, redirect, url_for, flash, abort
from .models import Status
from .forms import StatusForm, ConfirmForm
from .helper_role import Action, perm_required

# Blueprint
status_bp = Blueprint("status_bp", __name__)

@status_bp.route('/statuses/list')
@perm_required(Action.statuses_list)
def status_list():
    # select que retorna una llista de resultats
    statuses = Status.get_all()
    return render_template('statuses/list.html', statuses = statuses)

@status_bp.route('/statuses/create', methods = ['POST', 'GET'])
@perm_required(Action.statuses_create)
def status_create(): 

    # carrego el formulari amb l'objecte statuses
    form = StatusForm()

    if form.validate_on_submit(): # si s'ha fet submit al formulari
        new_status = Status()

        # dades del formulari a l'objecte status
        form.populate_obj(new_status)

        # insert!
        new_status.save()

        # https://en.wikipedia.org/wiki/Post/Redirect/Get
        flash("Nova estat creat", "success")
        return redirect(url_for('status_bp.status_list'))
    else: # GET
        return render_template('statuses/create.html', form = form)

@status_bp.route('/statuses/read/<int:status_id>')
@perm_required(Action.statuses_read)
def status_read(status_id):
    # select amb 1 resultat
    status = Status.get(status_id)

    if not status:
        abort(404)

    return render_template('statuses/read.html', status = status)

@status_bp.route('/statuses/update/<int:status_id>',methods = ['POST', 'GET'])
@perm_required(Action.statuses_update)
def status_update(status_id):
    # select amb 1 resultat
    status = Status.get(status_id)
    
    if not status:
        abort(404)

    # carrego el formulari amb l'objecte status
    form = StatusForm(obj = status)

    if form.validate_on_submit(): # si s'ha fet submit al formulari
        # dades del formulari a l'objecte status
        form.populate_obj(status)

        # update!
        status.update()

        # https://en.wikipedia.org/wiki/Post/Redirect/Get
        flash("Estat actualitzat", "success")
        return redirect(url_for('status_bp.status_read', status_id = status_id))
    else: # GET
        return render_template('statuses/update.html', status_id = status_id, form = form)

@status_bp.route('/statuses/delete/<int:status_id>',methods = ['GET', 'POST'])
@perm_required(Action.statuses_delete)
def status_delete(status_id):
    # select amb 1 resultat
    status = Status.get(status_id)

    if not status:
        abort(404)

    form = ConfirmForm()
    if form.validate_on_submit(): # si s'ha fet submit al formulari
        # delete!
        status.delete()

        flash("Estat esborrat", "success")
        return redirect(url_for('status_bp.status_list'))
    else: # GET
        return render_template('statuses/delete.html', form = form, status = status)