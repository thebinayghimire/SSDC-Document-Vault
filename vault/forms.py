from django import forms

from .models import Document, Folder
from .services import save_document_fields


class UploadForm(forms.Form):
    title = forms.CharField(max_length=200)
    file = forms.FileField(label="PDF or image")


class ImportForm(UploadForm):
    folder = forms.ModelChoiceField(queryset=Folder.objects.none(), label="Save to folder")

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


class MetadataForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "folder"]

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
