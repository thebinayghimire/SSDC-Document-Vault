from django import forms
from django.utils.translation import gettext_lazy as _

from .models import Document, Folder
from .services import save_document_fields


class UploadForm(forms.Form):
    title = forms.CharField(max_length=200, label=_("Title"))
    file = forms.FileField(label=_("PDF or image"))


class ImportForm(UploadForm):
    folder = forms.ModelChoiceField(queryset=Folder.objects.none(), label=_("Save to folder"))

    def __init__(self, *args, allowed_folders, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["folder"].queryset = allowed_folders


class ReplacementForm(UploadForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["title"].disabled = True
        self.fields["title"].widget = forms.HiddenInput()


class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ["name", "restricted"]
        labels = {"name": _("Name"), "restricted": _("Restricted")}


class MetadataForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "folder"]
        labels = {"title": _("Title"), "folder": _("Folder")}

    def __init__(self, *args, allowed_folders=None, actor=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.actor = actor
        self.fields["folder"].queryset = (
            allowed_folders if allowed_folders is not None else Folder.objects.none()
        )

    def save(self, commit=True):
        document = super().save(commit=False)
        if commit:
            self.instance = save_document_fields(document, self.changed_data, actor=self.actor)
        return self.instance
