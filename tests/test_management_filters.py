from urllib.parse import parse_qs

import pytest
from django.utils import timezone

from vault.models import Document, Folder, Version

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db


@pytest.fixture
def managed_documents(users, folder, document):
    archived = Document.objects.create(
        title="Archived report", folder=folder, created_by=users["manager"], archived=True
    )
    deleted = Document.objects.create(
        title="Deleted report",
        folder=folder,
        created_by=users["manager"],
        deleted_at=timezone.now(),
    )
    pending = Document.objects.create(
        title="Pending report", folder=folder, created_by=users["manager"]
    )
    rejected = Document.objects.create(
        title="Rejected report", folder=folder, created_by=users["manager"]
    )
    Version.objects.create(
        document=rejected,
        original_name="rejected.pdf",
        storage_key="originals/synthetic-rejected",
        mime_type="application/pdf",
        size=100,
        sha256="0" * 64,
        uploader=users["manager"],
        status=Version.Status.REJECTED,
    )
    hidden_folder = Folder.objects.create(name="Hidden board documents")
    Document.objects.create(
        title="Secret board report", folder=hidden_folder, created_by=users["admin"]
    )
    return {
        "published": document,
        "archived": archived,
        "deleted": deleted,
        "pending": pending,
        "rejected": rejected,
    }


@pytest.mark.parametrize("state", ["published", "archived", "deleted", "pending", "rejected"])
def test_management_state_filters_preserve_scope(client, users, managed_documents, state):
    authenticate_client(client, users["manager"])
    response = client.get("/manage/", {"state": state})
    assert response.status_code == 200
    assert list(response.context["page"]) == [managed_documents[state]]
    assert b"Secret board report" not in response.content
    assert b"Hidden board documents" not in response.content


def test_management_search_folder_and_sort_combine(client, users, folder, managed_documents):
    authenticate_client(client, users["manager"])
    response = client.get("/manage/", {"q": "report", "folder": folder.pk, "sort": "name"})
    docs = list(response.context["page"])
    assert len(docs) == 5
    assert [doc.title for doc in docs] == sorted(doc.title for doc in docs)
    assert list(response.context["management_folders"]) == [folder]
    assert client.get("/manage/", {"q": "Secret"}).context["page"].paginator.count == 0
    assert client.get("/manage/", {"folder": "invalid-uuid"}).context["page"].paginator.count == 0


def test_management_filters_survive_pagination(client, users, folder):
    Document.objects.bulk_create(
        [
            Document(
                title=f"Report {number:02}",
                folder=folder,
                created_by=users["manager"],
                archived=True,
            )
            for number in range(25)
        ]
    )
    authenticate_client(client, users["manager"])
    parameters = {"q": "Report", "state": "archived", "folder": str(folder.pk), "sort": "name"}
    response = client.get("/manage/", parameters)
    assert response.context["page"].has_next()
    assert parse_qs(response.context["pagination_query"]) == {
        key: [value] for key, value in parameters.items()
    }
    response = client.get("/manage/", {**parameters, "page": 2})
    assert [doc.title for doc in response.context["page"]] == ["Report 24"]
    assert "page" not in parse_qs(response.context["pagination_query"])


def test_staff_cannot_use_management_search(client, users):
    authenticate_client(client, users["alice"])
    assert client.get("/manage/?q=report&state=deleted").status_code == 404
