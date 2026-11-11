GLES_CreateTexture(SDL_Renderer * renderer, SDL_Texture * texture)
{
    GLES_RenderData *renderdata = (GLES_RenderData *) renderer->driverdata;
    GLES_TextureData *data;
    GLint internalFormat;
    GLenum format, type;
    int texture_w, texture_h;
    GLenum scaleMode;
    GLenum result;

    GLES_ActivateRenderer(renderer);

    switch (texture->format) {
    case SDL_PIXELFORMAT_ABGR8888:
        internalFormat = GL_RGBA;
        format = GL_RGBA;
        type = GL_UNSIGNED_BYTE;
        break;
    default:
        return SDL_SetError("Texture format not supported");
    }

    data = (GLES_TextureData *) SDL_calloc(1, sizeof(*data));
    if (!data) {
        return SDL_OutOfMemory();
    }

    if (texture->access == SDL_TEXTUREACCESS_STREAMING) {
        data->pitch = texture->w * SDL_BYTESPERPIXEL(texture->format);
        data->pixels = SDL_calloc(1, texture->h * data->pitch);
        if (!data->pixels) {
            SDL_free(data);
            return SDL_OutOfMemory();
        }
    }


    if (texture->access == SDL_TEXTUREACCESS_TARGET) {
        if (!renderdata->GL_OES_framebuffer_object_supported) {
            SDL_free(data);
            return SDL_SetError("GL_OES_framebuffer_object not supported");
        }
        data->fbo = GLES_GetFBO(renderer->driverdata, texture->w, texture->h);
    } else {
        data->fbo = NULL;
    }


    renderdata->glGetError();
    renderdata->glEnable(GL_TEXTURE_2D);
    renderdata->glGenTextures(1, &data->texture);
    result = renderdata->glGetError();
    if (result != GL_NO_ERROR) {
        if (texture->access == SDL_TEXTUREACCESS_STREAMING) {
            SDL_free(data->pixels);
        }
        SDL_free(data);
        return GLES_SetError("glGenTextures()", result);
    }

    data->type = GL_TEXTURE_2D;
    /* no NPOV textures allowed in OpenGL ES (yet) */
    texture_w = SDL_powerof2(texture->w);
    texture_h = SDL_powerof2(texture->h);
    data->texw = (GLfloat) texture->w / texture_w;
    data->texh = (GLfloat) texture->h / texture_h;

    data->format = format;
    data->formattype = type;
    scaleMode = (texture->scaleMode == SDL_ScaleModeNearest) ? GL_NEAREST : GL_LINEAR;
    renderdata->glBindTexture(data->type, data->texture);
    renderdata->glTexParameteri(data->type, GL_TEXTURE_MIN_FILTER, scaleMode);
    renderdata->glTexParameteri(data->type, GL_TEXTURE_MAG_FILTER, scaleMode);
    renderdata->glTexParameteri(data->type, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    renderdata->glTexParameteri(data->type, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    renderdata->glTexImage2D(data->type, 0, internalFormat, texture_w,
                             texture_h, 0, format, type, NULL);
    renderdata->glDisable(GL_TEXTURE_2D);
    renderdata->drawstate.texture = texture;
    renderdata->drawstate.texturing = SDL_FALSE;

    result = renderdata->glGetError();
    if (result != GL_NO_ERROR) {
        if (texture->access == SDL_TEXTUREACCESS_STREAMING) {
            SDL_free(data->pixels);
        }
        SDL_free(data);
        return GLES_SetError("glTexImage2D()", result);
    }

    texture->driverdata = data;
    return 0;
}
