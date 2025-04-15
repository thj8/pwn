let mapleader = ","

set nocompatible
set background=dark
syntax on
filetype off
set autochdir
set cursorline
set linespace=0
set number
set showmatch
set incsearch
set hlsearch
set ignorecase
set smartcase
set autoindent
set shiftwidth=2
set expandtab
set tabstop=2
set softtabstop=2
set cindent
set smartindent
set relativenumber
highjlight ctermbg=7 guibg=#A9A9A9

call plug#begin()
Plug 'neoclide/coc.nvim', {'branch': 'release'}
Plug 'tomtom/tcomment_vim'        " comment
call plug#end()

let g:coc_global_extensions = [
  \ 'coc-explorer',
  \ 'coc-json',
        \ 'coc-go',
        \ 'coc-marketplace',
        \ 'coc-translator',
  \ 'coc-pyright', ]

" edit & source vimrc
nnoremap <leader>s :source $MYVIMRC<cr>
nnoremap <leader>ev :edit $MYVIMRC<cr>

set encoding=utf-8
set nobackup
set nowritebackup
set updatetime=300
set signcolumn=yes
inoremap <silent><expr> <TAB>
      \ coc#pum#visible() ? coc#pum#next(1) :
      \ CheckBackspace() ? "\<Tab>" :
      \ coc#refresh()
inoremap <expr><S-TAB> coc#pum#visible() ? coc#pum#prev(1) : "\<C-h>"

inoremap <silent><expr> <CR> coc#pum#visible() ? coc#pum#confirm()
                              \: "\<C-g>u\<CR>\<c-r>=coc#on_enter()\<CR>"

function! CheckBackspace() abort
  let col = col('.') - 1
  return !col || getline('.')[col - 1]  =~# '\s'
endfunction

" Use <c-@> to trigger completion
inoremap <silent><expr> <c-@> coc#refresh()

" Use `[g` and `]g` to navigate diagnostics
" Use `:CocDiagnostics` to get all diagnostics of current buffer in location list
nmap <silent> [g <Plug>(coc-diagnostic-prev)
nmap <silent> ]g <Plug>(coc-diagnostic-next)

" GoTo code navigation
nmap <silent> gd <Plug>(coc-definition)
nmap <silent> gy <Plug>(coc-type-definition)
nmap <silent> gi <Plug>(coc-implementation)
nmap <silent> gr <Plug>(coc-references)

" Use K to show documentation in preview window
nnoremap <silent> K :call ShowDocumentation()<CR>

function! ShowDocumentation()
  if CocAction('hasProvider', 'hover')
    call CocActionAsync('doHover')
  else
    call feedkeys('K', 'in')
  endif
endfunction

" Highlight the symbol and its references when holding the cursor
autocmd CursorHold * silent call CocActionAsync('highlight')

" Symbol renaming
nmap <leader>rn <Plug>(coc-rename)

" Formatting selected code
xmap <leader>f  <Plug>(coc-format-selected)
nmap <leader>f  <Plug>(coc-format-selected)



" Configuration custom vim mapping
nmap ee :CocCommand explorer<CR>

" Save & quit
noremap Q :q<CR>
noremap <C-q> :qa<CR>
noremap <C-s> :w<CR>

"==={<CR>}
inoremap {{ {<CR>}<UP><ESC>o

"===========buffers===========
nnoremap <silent> bl :ls<CR>
nnoremap <silent> bu :enew<CR>
nnoremap <silent> bn :bnext<CR>
nnoremap <silent> bp :bprevious<CR>
nnoremap <silent> bd :bdelete<CR>


" ==================== tcomment_vim ====================
nnoremap ci cl
let g:tcomment_textobject_inlinecomment = ''
nmap <LEADER>cn g>c
vmap <LEADER>cn g>
nmap <LEADER>cu g<c
vmap <LEADER>cu g<
