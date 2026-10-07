from django import forms

from .models import Document, Folder


class UploadForm(forms.Form):
    title = forms.CharField(max_length=200)
    file = forms.FileField(label="PDF or image")


class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ["name", "restricted"]


class MetadataForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "folder"]

    def __init__(self, *args, allowed_folders=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["folder"].queryset = (
            allowed_folders if allowed_folders is not None else Folder.objects.none()
        )
