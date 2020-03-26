from django.db import IntegrityError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from .forms import TodoForm
from .models import Todo


def home(request):
    return render(request, 'Todo/home.html')


def signupuser(request):
    if request.method == 'GET':
        return render(request, 'Todo/signupuser.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('home')
            except IntegrityError:
                return render(request, 'Todo/signupuser.html', {'form': UserCreationForm(),
                                                                'error': 'The user name is already taken, Please try different one.'})
        else:
            return render(request, 'Todo/signupuser.html', {'form': UserCreationForm(),
                                                            'error': 'Passwords did not match.'})


def loginuser(request):
    if request.method == 'GET':
        return render(request, 'Todo/login.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, password=request.POST['password'], username=request.POST['username'])
        if user is None:
            return render(request, 'Todo/login.html',
                          {'form': AuthenticationForm(), 'error': 'Username or Password did not match.'})
        else:
            login(request, user)
            return redirect('currenttodo')


@login_required
def createtodo(request):
    if request.method == 'GET':
        return render(request, 'Todo/createtodo.html', {'form': TodoForm()})
    else:
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
            return redirect('currenttodo')
        except  ValueError:
            return render(request, 'Todo/createtodo.html',
                          {'form': TodoForm(), 'error': 'Bad data is passed in, Try again.'})


@login_required
def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')


@login_required
def currenttodo(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull=True)
    return render(request, 'Todo/current.html', {'todos': todos})


@login_required
def completedtodo(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull=False).order_by('-datecompleted')
    return render(request, 'Todo/completedtodo.html', {'todos': todos})


@login_required
def viewtodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'GET':
        form = TodoForm(instance=todo)
        return render(request, 'Todo/viewtodo.html', {'todo': todo, 'form': form})
    else:
        try:
            form = TodoForm(request.POST, instance=todo)
            form.save()
            return redirect('currenttodo')
        except ValueError:
            return render(request, 'Todo/viewtodo.html', {'todo': todo, 'form': form, 'error': 'Bad Info.'})


@login_required
def completetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.datecompleted = timezone.now()
        todo.save()
        return redirect('currenttodo')


@login_required
def deletetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('currenttodo')
