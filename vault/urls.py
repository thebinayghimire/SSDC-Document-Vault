from django.urls import path

from . import views

urlpatterns = [
    path(
        "documents/<uuid:document_id>/versions/<uuid:version_id>/restore/",
        views.restore_version,
        name="restore_version",
    ),
    path("", views.library, name="library"),
    path("folders/new/", views.create_folder, name="create_root_folder"),
    path("folders/<uuid:folder_id>/", views.library, name="folder"),
    path("folders/<uuid:folder_id>/new/", views.create_folder, name="create_folder"),
    path("folders/<uuid:folder_id>/upload/", views.upload, name="upload"),
    path("manage/", views.management, name="management"),
    path("documents/<uuid:document_id>/", views.preview, name="preview"),
    path("documents/<uuid:document_id>/content/", views.content, name="content"),
    path(
        "documents/<uuid:document_id>/thumbnail/",
        views.content,
        {"thumbnail": True},
        name="thumbnail",
    ),
    path("documents/<uuid:document_id>/manage/", views.manage_document, name="manage_document"),
    path("documents/<uuid:document_id>/replace/", views.upload, name="replace"),
    path("documents/<uuid:document_id>/actions/<str:action>/", views.lifecycle, name="lifecycle"),
]
